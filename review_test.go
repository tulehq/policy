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
