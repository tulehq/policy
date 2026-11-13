package policy

import "testing"

func trustDoc(principal string) string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":` + principal +
		`,"Action":"sts:AssumeRole"}}`
}

// Rows follow "AWS JSON policy elements: Principal",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html.
var trustCases = []struct { //nolint:govet // fieldalignment: field order reads as the rows do.
	name, principal, caller string
	ctx                     map[string][]string
	want                    bool
}{
	// "The account ARN and the shortened account ID behave the same way.
	// Both delegate permissions to the account. Using the account ARN in
	// the Principal element does not limit permissions to only the root
	// user of the account."
	{
		"account id user",
		`{"AWS":"123456789012"}`,
		"arn:aws:iam::123456789012:user/alice",
		nil,
		true,
	},
	{
		"account root arn user", `{"AWS":"arn:aws:iam::123456789012:root"}`,
		"arn:aws:iam::123456789012:user/alice", nil, true,
	},
	{
		"account root arn session", `{"AWS":"arn:aws:iam::123456789012:root"}`,
		"arn:aws:sts::123456789012:assumed-role/r/s", nil, true,
	},
	{
		"account root arn root",
		`{"AWS":"arn:aws:iam::123456789012:root"}`,
		"arn:aws:iam::123456789012:root",
		nil,
		true,
	},
	{
		"account id other account",
		`{"AWS":"123456789012"}`,
		"arn:aws:iam::555555555555:user/alice",
		nil,
		false,
	},
	// "This is a logical OR and not a logical AND"
	{
		"account list",
		`{"AWS":["123456789012","555555555555"]}`,
		"arn:aws:iam::555555555555:user/bob",
		nil,
		true,
	},
	// IAM user principals; "the user name part of the ARN is case
	// sensitive."
	{
		"user",
		`{"AWS":"arn:aws:iam::123456789012:user/alice"}`,
		"arn:aws:iam::123456789012:user/alice",
		nil,
		true,
	},
	{
		"user other",
		`{"AWS":"arn:aws:iam::123456789012:user/alice"}`,
		"arn:aws:iam::123456789012:user/bob",
		nil,
		false,
	},
	{
		"user case",
		`{"AWS":"arn:aws:iam::123456789012:user/alice"}`,
		"arn:aws:iam::123456789012:user/Alice",
		nil,
		false,
	},
	// IAM role principals: a role's sessions are its principals.
	{
		"role session", `{"AWS":"arn:aws:iam::123456789012:role/deploy"}`,
		"arn:aws:sts::123456789012:assumed-role/deploy/ci-run", nil, true,
	},
	{
		"role with path session", `{"AWS":"arn:aws:iam::123456789012:role/team/deploy"}`,
		"arn:aws:sts::123456789012:assumed-role/deploy/ci-run", nil, true,
	},
	{
		"role other session", `{"AWS":"arn:aws:iam::123456789012:role/deploy"}`,
		"arn:aws:sts::123456789012:assumed-role/admin/ci-run", nil, false,
	},
	{
		"role other account", `{"AWS":"arn:aws:iam::123456789012:role/deploy"}`,
		"arn:aws:sts::555555555555:assumed-role/deploy/ci-run", nil, false,
	},
	{
		"role via PrincipalArn", `{"AWS":"arn:aws:iam::123456789012:role/team/deploy"}`,
		"arn:aws:sts::123456789012:assumed-role/deploy/s",
		ctx("aws:PrincipalArn", "arn:aws:iam::123456789012:role/team/deploy"), true,
	},
	{
		"role does not match a user", `{"AWS":"arn:aws:iam::123456789012:role/deploy"}`,
		"arn:aws:iam::123456789012:user/deploy", nil, false,
	},
	// Role session principals.
	{
		"session", `{"AWS":"arn:aws:sts::123456789012:assumed-role/r/s1"}`,
		"arn:aws:sts::123456789012:assumed-role/r/s1", nil, true,
	},
	{
		"session other", `{"AWS":"arn:aws:sts::123456789012:assumed-role/r/s1"}`,
		"arn:aws:sts::123456789012:assumed-role/r/s2", nil, false,
	},
	// "the following elements are equivalent: "Principal": "*" and
	// "Principal" : { "AWS" : "*" }"
	{"star", `"*"`, "arn:aws:iam::999999999999:user/x", nil, true},
	{"AWS star", `{"AWS":"*"}`, "arn:aws:iam::999999999999:user/x", nil, true},
	// AWS service principals.
	{
		"service", `{"Service":["ecs.amazonaws.com","elasticloadbalancing.amazonaws.com"]}`,
		"elasticloadbalancing.amazonaws.com", nil, true,
	},
	{"service other", `{"Service":"ecs.amazonaws.com"}`, "lambda.amazonaws.com", nil, false},
	{
		"service does not match account",
		`{"Service":"123456789012"}`,
		"arn:aws:iam::123456789012:user/a",
		nil,
		false,
	},
}

func TestAllowsPrincipal(t *testing.T) {
	for _, c := range trustCases {
		t.Run(c.name, func(t *testing.T) {
			p := mustParse(t, trustDoc(c.principal))
			if got := AllowsPrincipal(p, "sts:AssumeRole", c.caller, c.ctx); got != c.want {
				t.Errorf("AllowsPrincipal = %v, want %v", got, c.want)
			}
		})
	}
}

func TestAllowsPrincipalStatements(t *testing.T) {
	const caller = "arn:aws:iam::123456789012:user/alice"
	doc := `{"Version":"2012-10-17","Statement":[
	  {"Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"sts:AssumeRole",
	   "Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}},
	  {"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::123456789012:user/mallory"},"Action":"sts:*"},
	  {"Effect":"Deny","NotPrincipal":{"AWS":["123456789012","arn:aws:iam::123456789012:user/alice"]},
	   "Action":"sts:TagSession"}]}`
	p := mustParse(t, doc)
	mfa := ctx("aws:MultiFactorAuthPresent", "true")
	checks := []struct { //nolint:govet // fieldalignment: field order reads as the rows do.
		name, action, caller string
		ctx                  map[string][]string
		want                 bool
	}{
		{"allowed with condition", "sts:AssumeRole", caller, mfa, true},
		{"condition fails", "sts:AssumeRole", caller, nil, false},
		{"action case", "STS:assumerole", caller, mfa, true},
		{"other action", "sts:AssumeRoleWithSAML", caller, mfa, false},
		{
			"explicit deny wins",
			"sts:AssumeRole",
			"arn:aws:iam::123456789012:user/mallory",
			mfa,
			false,
		},
		{
			"NotPrincipal excluded caller not denied, not allowed",
			"sts:TagSession",
			caller,
			mfa,
			false,
		},
	}
	for _, c := range checks {
		if got := AllowsPrincipal(p, c.action, c.caller, c.ctx); got != c.want {
			t.Errorf("%s: AllowsPrincipal = %v, want %v", c.name, got, c.want)
		}
	}
	if AllowsPrincipal(nil, "sts:AssumeRole", caller, nil) {
		t.Error("a nil trust policy must allow nothing")
	}
	identity := mustParse(t, allowAll)
	if AllowsPrincipal(identity, "sts:AssumeRole", caller, nil) {
		t.Error("a statement without Principal must allow nobody")
	}
}

func TestEvaluateResult(t *testing.T) {
	a := mustParse(
		t,
		`{"Version":"2012-10-17","Statement":[{"Sid":"A","Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
	)
	d := mustParse(
		t,
		`{"Version":"2012-10-17","Statement":[{"Sid":"D","Effect":"Deny","Action":"s3:Delete*","Resource":"*"}]}`,
	)
	r := req("s3:DeleteObject", "arn:aws:s3:::b/k")
	if got, want := Evaluate(
		r,
		a,
		nil,
		d,
	), (Result{Decision: ExplicitDeny, Policy: 2, Sid: "D"}); got != want {
		t.Errorf("deny: %+v, want %+v", got, want)
	}
	if got, want := Evaluate(
		req("s3:GetObject", "x"),
		nil,
		a,
		d,
	), (Result{Decision: Allow, Policy: 1, Sid: "A"}); got != want {
		t.Errorf("allow: %+v, want %+v", got, want)
	}
	if got, want := Evaluate(
		req("sqs:SendMessage", "x"),
		a,
		d,
	), (Result{Decision: ImplicitDeny, Policy: -1}); got != want {
		t.Errorf("implicit: %+v, want %+v", got, want)
	}
	if got, want := Evaluate(r), (Result{Decision: ImplicitDeny, Policy: -1}); got != want {
		t.Errorf("no policies: %+v, want %+v", got, want)
	}
	for d, want := range map[Decision]string{
		ImplicitDeny: "ImplicitDeny", Allow: "Allow", ExplicitDeny: "ExplicitDeny", Decision(7): "Decision(7)",
	} {
		if d.String() != want {
			t.Errorf("String() = %q, want %q", d.String(), want)
		}
	}
}
