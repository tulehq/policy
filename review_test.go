package policy

import (
	"errors"
	"testing"
)

// A statement with a Principal, which the lenient Parse accepts, is not an
// identity statement: Evaluate must not apply it to anyone.
func TestEvaluateSkipsPrincipalStatements(t *testing.T) {
	for _, doc := range []string{
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
			`"Principal":{"AWS":"arn:aws:iam::111122223333:user/bob"},"Action":"s3:*","Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Deny",` +
			`"NotPrincipal":{"AWS":"arn:aws:iam::111122223333:user/bob"},"Action":"s3:*","Resource":"*"}}`,
	} {
		r := req("s3:GetObject", "arn:aws:s3:::b/k")
		if got := Evaluate(r, mustParse(t, doc)); got.Decision != ImplicitDeny {
			t.Errorf("Evaluate(%s) = %+v, want ImplicitDeny", doc, got)
		}
	}
}

// A statement with a Resource is not a trust statement.
func TestTrustMatchSkipsResourceStatements(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*",` +
		`"Action":"sts:AssumeRole","Resource":"*"}}`
	got := TrustMatch(
		mustParse(t, doc),
		"sts:AssumeRole",
		"arn:aws:iam::111122223333:user/alice",
		nil,
	)
	if got.Decision != ImplicitDeny {
		t.Errorf("TrustMatch = %+v, want ImplicitDeny", got)
	}
}

// ARN operators: a request value is an ARN only with the arn prefix, a
// partition, a service and six fields; anything else is an invalid value,
// which never grants and always denies. These are the review's probes.
var arnShapeCases = []evalCase{
	{
		"Allow ArnNotLike five colons",
		[]string{condPolicy("Allow",
			`{"ArnNotLike":{"aws:SourceArn":"arn:aws:sns:*:*:blocked"}}`)},
		anyRequest(ctx("aws:SourceArn", "junk:::::")), ImplicitDeny,
	},
	{
		"Allow ArnNotEquals wrong prefix",
		[]string{condPolicy("Allow",
			`{"ArnNotEquals":{"aws:SourceArn":"arn:aws:sns:us-east-1:1:t"}}`)},
		anyRequest(ctx("aws:SourceArn", "xyz:aws:sns:us-east-1:1:t")), ImplicitDeny,
	},
	{
		"Allow ArnNotEquals empty service",
		[]string{condPolicy("Allow",
			`{"ArnNotEquals":{"aws:SourceArn":"arn:aws:sns:us-east-1:1:t"}}`)},
		anyRequest(ctx("aws:SourceArn", "arn:aws::us-east-1:1:t")), ImplicitDeny,
	},
	{
		"Deny ArnLike uppercase prefix",
		[]string{allowAll, condPolicy("Deny",
			`{"ArnLike":{"aws:SourceArn":"arn:aws:sns:*:*:*"}}`)},
		anyRequest(ctx("aws:SourceArn", "ARN:aws:sns:us-east-1:1:t")), ExplicitDeny,
	},
	// A colon in a variable's value stays in its field.
	{
		"Allow ArnEquals variable cannot shift fields",
		[]string{condPolicy("Allow",
			`{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:${aws:RequestTag/r}:111122223333:t"}}`)},
		anyRequest(ctx("aws:SourceArn", "arn:aws:sns:us-east-1:999999999999:111122223333:t",
			"aws:RequestTag/r", "us-east-1:999999999999")), ImplicitDeny,
	},
	{
		"Deny ArnLike variable in field",
		[]string{allowAll, condPolicy("Deny",
			`{"ArnLike":{"aws:SourceArn":"arn:aws:sns:${aws:RequestTag/r}:111122223333:t"}}`)},
		anyRequest(
			ctx(
				"aws:SourceArn",
				"arn:aws:sns:us-east-1:111122223333:t",
				"aws:RequestTag/r",
				"us-east-1",
			),
		),
		ExplicitDeny,
	},
	// A whole-value variable supplies the structure; its value stays
	// literal, and a non-ARN value never grants.
	{
		"Allow ArnLike whole variable literal star",
		[]string{condPolicy("Allow",
			`{"ArnLike":{"k:arn":"${k:v}"}}`)},
		anyRequest(ctx("k:arn", "arn:aws:s3:::bucket", "k:v", "arn:aws:s3:::*")), ImplicitDeny,
	},
	{
		"Allow ArnLike whole variable",
		[]string{condPolicy("Allow", `{"ArnLike":{"k:arn":"${k:v}"}}`)},
		anyRequest(ctx("k:arn", "arn:aws:s3:::b", "k:v", "arn:aws:s3:::b")), Allow,
	},
	{
		"Allow ArnNotLike whole variable not an arn",
		[]string{condPolicy("Allow",
			`{"ArnNotLike":{"k:arn":"${k:v}"}}`)},
		anyRequest(ctx("k:arn", "arn:aws:s3:::b", "k:v", "b")), ImplicitDeny,
	},
}

func TestARNShapes(t *testing.T) { runEvalCases(t, arnShapeCases) }

// Principal types stay apart: each takes only its own kind of identifier.
func TestPrincipalTypes(t *testing.T) {
	trust := func(principal string) string {
		return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":` + principal +
			`,"Action":"sts:AssumeRole"}}`
	}
	for _, bad := range []string{
		`{"Service":"arn:aws:iam::111122223333:user/alice"}`,
		`{"Service":"123456789012"}`,
		`{"AWS":"ec2.amazonaws.com"}`,
		`{"AWS":"arn:aws:s3:::bucket"}`,
		`{"Federated":"111122223333"}`,
		`{"Federated":"arn:aws:iam::111122223333:user/alice"}`,
		`{"CanonicalUser":"arn:aws:iam::111122223333:user/alice"}`,
	} {
		_, err := ParseTrust([]byte(trust(bad)))
		var pe *ParseError
		if !errors.As(err, &pe) || pe.Message != msgPrincipal {
			t.Errorf("ParseTrust(%s) = %v, want %q", bad, err, msgPrincipal)
		}
	}
	for _, good := range []string{
		`{"Service":"ec2.amazonaws.com"}`,
		`{"Federated":"accounts.google.com"}`,
		`{"Federated":"arn:aws:iam::111122223333:saml-provider/corp"}`,
		`{"Federated":"arn:aws:iam::111122223333:oidc-provider/tokens.actions.githubusercontent.com"}`,
		`{"CanonicalUser":"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"}`,
		`{"AWS":["123456789012","arn:aws:iam::123456789012:root","arn:aws:sts::123456789012:assumed-role/r/s"]}`,
	} {
		if _, err := ParseTrust([]byte(trust(good))); err != nil {
			t.Errorf("ParseTrust(%s) = %v", good, err)
		}
	}
}
