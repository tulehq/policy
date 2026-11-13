package policy

import (
	"errors"
	"testing"
)

const trustPolicy = `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
	`"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`

var kindCases = []struct {
	name, doc        string
	identity, trust  string // the error message, or "" when accepted
	identityOK, trOK bool
}{
	{"identity policy", allowAll, "", msgNoPrincipal, true, false},
	{"trust policy", trustPolicy, msgHasPrincipal, "", false, true},
	{
		"identity with NotPrincipal", `{"Version":"2012-10-17","Statement":{"Effect":"Deny",` +
			`"NotPrincipal":{"AWS":"123456789012"},"Action":"*","Resource":"*"}}`,
		msgHasPrincipal, "Has prohibited field NotPrincipal", false, false,
	},
	{
		"trust with Resource", `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
			`"Principal":{"AWS":"123456789012"},"Action":"sts:AssumeRole","Resource":"*"}}`,
		msgHasPrincipal, "Has prohibited field Resource", false, false,
	},
	{
		"trust with NotResource", `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
			`"Principal":{"AWS":"123456789012"},"Action":"sts:AssumeRole","NotResource":"arn:aws:s3:::b"}}`,
		msgHasPrincipal, "Has prohibited field NotResource", false, false,
	},
	{
		"trust with NotPrincipal", `{"Version":"2012-10-17","Statement":{"Effect":"Deny",` +
			`"NotPrincipal":{"AWS":"123456789012"},"Action":"sts:AssumeRole"}}`,
		msgHasPrincipal, "Has prohibited field NotPrincipal", false, false,
	},
	{
		"no principal, no resource",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole"}}`,
		msgNoResources,
		msgNoPrincipal,
		false,
		false,
	},
	{
		"mixed statements", `{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Action":"*","Resource":"*"},` +
			`{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`,
		msgHasPrincipal, msgNoPrincipal, false, false,
	},
	{"malformed either way", `{"Statement":[]}`, msgSyntax, msgSyntax, false, false},
}

func TestParseKinds(t *testing.T) {
	for _, c := range kindCases {
		check := func(kind string, parse func([]byte) (*Policy, error), ok bool, msg string) {
			p, err := parse([]byte(c.doc))
			if ok {
				if err != nil || p == nil {
					t.Errorf("%s as %s: %v, want accepted", c.name, kind, err)
				}
				return
			}
			var pe *ParseError
			if !errors.As(err, &pe) || pe.Message != msg {
				t.Errorf("%s as %s: %v, want %q", c.name, kind, err, msg)
			}
		}
		check("identity", ParseIdentity, c.identityOK, c.identity)
		check("trust", ParseTrust, c.trOK, c.trust)
	}
	// Parse stays kind-agnostic.
	for _, doc := range []string{allowAll, trustPolicy, kindCases[7].doc} {
		if _, err := Parse([]byte(doc)); err != nil {
			t.Errorf("Parse(%s): %v", doc, err)
		}
	}
}

var trustMatchCases = []struct {
	name, principal, caller string
	want                    TrustResult
}{
	{
		"account id", `{"AWS":"123456789012"}`, "arn:aws:iam::123456789012:user/alice",
		TrustResult{Decision: Allow, Sid: "T"},
	},
	{
		"root arn",
		`{"AWS":"arn:aws:iam::123456789012:root"}`,
		"arn:aws:sts::123456789012:assumed-role/r/s",
		TrustResult{Decision: Allow, Sid: "T"},
	},
	{
		"user arn",
		`{"AWS":"arn:aws:iam::123456789012:user/alice"}`,
		"arn:aws:iam::123456789012:user/alice",
		TrustResult{Decision: Allow, Direct: true, Sid: "T"},
	},
	{
		"role arn session",
		`{"AWS":"arn:aws:iam::123456789012:role/r"}`,
		"arn:aws:sts::123456789012:assumed-role/r/s",
		TrustResult{Decision: Allow, Direct: true, Sid: "T"},
	},
	{
		"session arn", `{"AWS":"arn:aws:sts::123456789012:assumed-role/r/s"}`,
		"arn:aws:sts::123456789012:assumed-role/r/s",
		TrustResult{Decision: Allow, Direct: true, Sid: "T"},
	},
	// Direct only within the role's account (123456789012 here).
	{
		"star, same account",
		`"*"`,
		"arn:aws:iam::123456789012:user/x",
		TrustResult{Decision: Allow, Direct: true, Sid: "T"},
	},
	{
		"user, other account",
		`{"AWS":"arn:aws:iam::999999999999:user/eve"}`,
		"arn:aws:iam::999999999999:user/eve",
		TrustResult{Decision: Allow, Sid: "T"},
	},
	{
		"session, other account", `{"AWS":"arn:aws:iam::999999999999:role/r"}`,
		"arn:aws:sts::999999999999:assumed-role/r/s",
		TrustResult{Decision: Allow, Sid: "T"},
	},
	{
		"star, other account",
		`"*"`,
		"arn:aws:iam::999999999999:user/x",
		TrustResult{Decision: Allow, Sid: "T"},
	},
	{
		"AWS star, other account",
		`{"AWS":"*"}`,
		"arn:aws:iam::999999999999:user/x",
		TrustResult{Decision: Allow, Sid: "T"},
	},
	{
		"service", `{"Service":"lambda.amazonaws.com"}`, "lambda.amazonaws.com",
		TrustResult{Decision: Allow, Sid: "T"},
	},
	{
		"account and user, user is the caller",
		`{"AWS":["123456789012","arn:aws:iam::123456789012:user/alice"]}`,
		"arn:aws:iam::123456789012:user/alice",
		TrustResult{Decision: Allow, Direct: true, Sid: "T"},
	},
	{
		"account and user, other caller",
		`{"AWS":["123456789012","arn:aws:iam::123456789012:user/alice"]}`,
		"arn:aws:iam::123456789012:user/bob",
		TrustResult{Decision: Allow, Sid: "T"},
	},
	{
		"no match",
		`{"AWS":"arn:aws:iam::123456789012:user/alice"}`,
		"arn:aws:iam::123456789012:user/bob",
		TrustResult{Decision: ImplicitDeny},
	},
}

func TestTrustMatch(t *testing.T) {
	for _, c := range trustMatchCases {
		doc := `{"Version":"2012-10-17","Statement":{"Sid":"T","Effect":"Allow","Principal":` + c.principal +
			`,"Action":"sts:AssumeRole"}}`
		p := mustParse(t, doc)
		if got := TrustMatch(p, "123456789012", "sts:AssumeRole", c.caller, nil); got != c.want {
			t.Errorf("%s: TrustMatch = %+v, want %+v", c.name, got, c.want)
		}
		if got := AllowsPrincipal(
			p,
			"sts:AssumeRole",
			c.caller,
			nil,
		); got != (c.want.Decision == Allow) {
			t.Errorf("%s: AllowsPrincipal = %v", c.name, got)
		}
	}
}

func TestTrustMatchStatements(t *testing.T) {
	const alice = "arn:aws:iam::123456789012:user/alice"
	p := mustParse(t, `{"Version":"2012-10-17","Statement":[
	  {"Sid":"Account","Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"sts:AssumeRole"},
	  {"Sid":"Alice","Effect":"Allow","Principal":{"AWS":"`+alice+`"},"Action":"sts:AssumeRole"},
	  {"Sid":"Account2","Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"sts:AssumeRole"},
	  {"Sid":"NoMallory","Effect":"Deny","Principal":{"AWS":"arn:aws:iam::123456789012:user/mallory"},
	   "Action":"sts:*"}]}`)
	checks := []struct {
		caller string
		want   TrustResult
	}{
		// A later direct statement wins over an earlier account one.
		{alice, TrustResult{Decision: Allow, Direct: true, Sid: "Alice"}},
		// Otherwise the first allowing statement names the decision.
		{"arn:aws:iam::123456789012:user/bob", TrustResult{Decision: Allow, Sid: "Account"}},
		{
			"arn:aws:iam::123456789012:user/mallory",
			TrustResult{Decision: ExplicitDeny, Sid: "NoMallory"},
		},
		{"arn:aws:iam::555555555555:user/eve", TrustResult{Decision: ImplicitDeny}},
	}
	for _, c := range checks {
		if got := TrustMatch(p, "123456789012", "sts:AssumeRole", c.caller, nil); got != c.want {
			t.Errorf("%s: TrustMatch = %+v, want %+v", c.caller, got, c.want)
		}
	}
	if got := TrustMatch(
		nil,
		"123456789012",
		"sts:AssumeRole",
		alice,
		nil,
	); got != (TrustResult{Decision: ImplicitDeny}) {
		t.Errorf("nil trust: %+v", got)
	}
	deny := mustParse(t, `{"Version":"2012-10-17","Statement":[
	  {"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"},
	  {"Sid":"OthersOut","Effect":"Deny","NotPrincipal":{"AWS":"`+alice+`"},"Action":"sts:AssumeRole"}]}`)
	if got := TrustMatch(
		deny,
		"123456789012",
		"sts:AssumeRole",
		"arn:aws:iam::123456789012:user/bob",
		nil,
	); got !=
		(TrustResult{Decision: ExplicitDeny, Sid: "OthersOut"}) {
		t.Errorf("NotPrincipal deny: %+v", got)
	}
	if got := TrustMatch(
		deny,
		"123456789012",
		"sts:AssumeRole",
		alice,
		nil,
	); got != (TrustResult{Decision: Allow, Direct: true}) {
		t.Errorf("NotPrincipal excluded: %+v", got)
	}
}
