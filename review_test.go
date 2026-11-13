package policy

import "testing"

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
