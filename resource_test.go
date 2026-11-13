package policy

import "testing"

const (
	acct  = "111122223333"
	other = "444455556666"
)

var (
	devUser = Caller{
		AccountID:    acct,
		ARN:          "arn:aws:iam::" + acct + ":user/team/dev",
		PrincipalARN: "arn:aws:iam::" + acct + ":user/team/dev",
		UserID:       "AIDADEVEXAMPLE0000001",
		Type:         PrincipalTypeUser,
	}
	session = Caller{
		AccountID:    acct,
		ARN:          "arn:aws:sts::" + acct + ":assumed-role/Reader/s1",
		PrincipalARN: "arn:aws:iam::" + acct + ":role/ops/Reader",
		UserID:       "AROAREADEREXAMPLE0001:s1",
		Type:         PrincipalTypeAssumedRole,
	}
	// orphan is session after its role was deleted.
	orphan = Caller{
		AccountID: acct,
		ARN:       session.ARN,
		UserID:    session.UserID,
		Type:      PrincipalTypeAssumedRole,
	}
	root = Caller{
		AccountID:    acct,
		ARN:          "arn:aws:iam::" + acct + ":root",
		PrincipalARN: "arn:aws:iam::" + acct + ":root",
		UserID:       acct,
		Type:         PrincipalTypeAccount,
	}
)

// callerMatchCases: how a Principal value names a caller.
var callerMatchCases = []struct { //nolint:govet // fieldalignment: field order reads as the rows do.
	name, principal string
	caller          Caller
	want            matchKind
}{
	{"star", `"*"`, devUser, matchDirect},
	{"aws star", `{"AWS":"*"}`, orphan, matchDirect},
	{"account id", `{"AWS":"` + acct + `"}`, devUser, matchAccount},
	{"account id other", `{"AWS":"` + other + `"}`, devUser, matchNone},
	{"root arn", `{"AWS":"arn:aws:iam::` + acct + `:root"}`, session, matchAccount},
	{"root arn other partition", `{"AWS":"arn:aws-cn:iam::` + acct + `:root"}`, devUser, matchNone},
	{"root arn orphan", `{"AWS":"arn:aws:iam::` + acct + `:root"}`, orphan, matchAccount},
	{"user arn", `{"AWS":"` + devUser.ARN + `"}`, devUser, matchDirect},
	{"user arn without path", `{"AWS":"arn:aws:iam::` + acct + `:user/dev"}`, devUser, matchNone},
	{"user arn case", `{"AWS":"arn:aws:iam::` + acct + `:user/team/Dev"}`, devUser, matchNone},
	{"user arn not a session", `{"AWS":"` + devUser.ARN + `"}`, session, matchNone},
	{"role arn session", `{"AWS":"` + session.PrincipalARN + `"}`, session, matchDirect},
	{
		"role arn without path",
		`{"AWS":"arn:aws:iam::` + acct + `:role/Reader"}`,
		session,
		matchNone,
	},
	{"role arn orphan", `{"AWS":"` + session.PrincipalARN + `"}`, orphan, matchNone},
	{
		"role arn not a user",
		`{"AWS":"` + session.PrincipalARN + `"}`,
		Caller{
			AccountID:    acct,
			ARN:          devUser.ARN,
			PrincipalARN: session.PrincipalARN,
			Type:         PrincipalTypeUser,
		},
		matchNone,
	},
	{"session arn", `{"AWS":"` + session.ARN + `"}`, session, matchDirect},
	{
		"session arn other session",
		`{"AWS":"arn:aws:sts::` + acct + `:assumed-role/Reader/s2"}`,
		session,
		matchNone,
	},
	{"session arn orphan", `{"AWS":"` + session.ARN + `"}`, orphan, matchNone},
	{"user id", `{"AWS":"AIDADEVEXAMPLE0000001"}`, devUser, matchDirect},
	{"role id", `{"AWS":"AROAREADEREXAMPLE0001"}`, session, matchDirect},
	{"role id prefix only", `{"AWS":"AROAREADEREXAMPLE000"}`, session, matchNone},
	{"role id orphan", `{"AWS":"AROAREADEREXAMPLE0001"}`, orphan, matchNone},
	{"user id not a session", `{"AWS":"AIDADEVEXAMPLE0000001"}`, Caller{
		AccountID: acct, ARN: session.ARN, PrincipalARN: session.PrincipalARN,
		UserID: "AIDADEVEXAMPLE0000001", Type: PrincipalTypeAssumedRole,
	}, matchNone},
	{"service", `{"Service":"s3.amazonaws.com"}`, devUser, matchNone},
	{
		"federated user arn",
		`{"AWS":"arn:aws:sts::` + acct + `:federated-user/dev"}`,
		devUser,
		matchNone,
	},
	{"closest of several", `{"AWS":["` + acct + `","` + devUser.ARN + `"]}`, devUser, matchDirect},
	{
		"unknown type",
		`{"AWS":"` + devUser.ARN + `"}`,
		Caller{AccountID: acct, ARN: devUser.ARN},
		matchNone,
	},
	{
		"unknown type account",
		`{"AWS":"` + acct + `"}`,
		Caller{AccountID: acct, ARN: devUser.ARN},
		matchAccount,
	},
}

func TestCallerMatch(t *testing.T) {
	for _, c := range callerMatchCases {
		t.Run(c.name, func(t *testing.T) {
			p := mustParseResource(
				t,
				resourceDoc("Allow", `"Principal":`+c.principal, bucketObjects),
			)
			if got := p.statements[0].principal.callerMatch(c.caller); got != c.want {
				t.Fatalf("callerMatch = %v, want %v", got, c.want)
			}
		})
	}
}

// excludesCases: whether NotPrincipal exempts a caller from its Deny.
var excludesCases = []struct { //nolint:govet // fieldalignment: field order reads as the rows do.
	name, principal string
	caller          Caller
	want            bool
}{
	{"star", `"*"`, orphan, true},
	{"user and account", `{"AWS":["` + devUser.ARN + `","` + acct + `"]}`, devUser, true},
	{
		"user and root arn",
		`{"AWS":["` + devUser.ARN + `","arn:aws:iam::` + acct + `:root"]}`,
		devUser,
		true,
	},
	{"user only", `{"AWS":"` + devUser.ARN + `"}`, devUser, false},
	{"account only", `{"AWS":"` + acct + `"}`, devUser, false},
	{"account only root", `{"AWS":"` + acct + `"}`, root, true},
	{"role and account", `{"AWS":["` + session.PrincipalARN + `","` + acct + `"]}`, session, true},
	{"session and account", `{"AWS":["` + session.ARN + `","` + acct + `"]}`, session, true},
	{
		"role and account orphan",
		`{"AWS":["` + session.PrincipalARN + `","` + acct + `"]}`,
		orphan,
		false,
	},
	{
		"other user and account",
		`{"AWS":["arn:aws:iam::` + acct + `:user/ops","` + acct + `"]}`,
		devUser,
		false,
	},
	{"user and other account", `{"AWS":["` + devUser.ARN + `","` + other + `"]}`, devUser, false},
}

func TestExcludes(t *testing.T) {
	for _, c := range excludesCases {
		t.Run(c.name, func(t *testing.T) {
			p := mustParseResource(
				t,
				resourceDoc("Deny", `"NotPrincipal":`+c.principal, bucketObjects),
			)
			if got := p.statements[0].principal.excludes(c.caller); got != c.want {
				t.Fatalf("excludes = %v, want %v", got, c.want)
			}
		})
	}
}

func mustParseResource(t testing.TB, doc string) *Policy {
	t.Helper()
	p, err := ParseResource([]byte(doc))
	if err != nil {
		t.Fatalf("ParseResource(%s): %v", doc, err)
	}
	return p
}

func TestDecide(t *testing.T) {
	cases := []struct { //nolint:govet // fieldalignment: field order reads as the rows do.
		id, res      Decision
		direct, same bool
		want         Decision
		reason       Reason
	}{
		{ExplicitDeny, ExplicitDeny, false, true, ExplicitDeny, IdentityDeny},
		{Allow, ExplicitDeny, false, true, ExplicitDeny, ResourceDeny},
		{Allow, ImplicitDeny, false, true, Allow, NoReason},
		{ImplicitDeny, Allow, true, true, Allow, NoReason},
		{ImplicitDeny, Allow, false, true, ImplicitDeny, NoIdentityAllow},
		{ImplicitDeny, ImplicitDeny, false, true, ImplicitDeny, NoIdentityAllow},
		{Allow, Allow, false, false, Allow, NoReason},
		{Allow, ImplicitDeny, false, false, ImplicitDeny, NoResourceAllow},
		{ImplicitDeny, Allow, true, false, ImplicitDeny, NoIdentityAllow},
		{ImplicitDeny, ImplicitDeny, false, false, ImplicitDeny, NoIdentityAllow},
	}
	for _, c := range cases {
		d, r := decide(c.id, c.res, c.direct, c.same)
		if d != c.want || r != c.reason {
			t.Errorf("decide(%v, %v, direct=%v, same=%v) = %v, %v; want %v, %v",
				c.id, c.res, c.direct, c.same, d, r, c.want, c.reason)
		}
	}
}

func TestReasonMessage(t *testing.T) {
	for r, want := range map[Reason]string{
		NoReason:        "",
		IdentityDeny:    "with an explicit deny in an identity-based policy",
		ResourceDeny:    "with an explicit deny in a resource-based policy",
		NoIdentityAllow: "because no identity-based policy allows the s3:GetObject action",
		NoResourceAllow: "because no resource-based policy allows the s3:GetObject action",
		Reason(9):       "",
	} {
		if got := r.Message("s3:GetObject"); got != want {
			t.Errorf("%v.Message = %q, want %q", r, got, want)
		}
	}
	if Reason(9).String() != "Reason(9)" || NoResourceAllow.String() != "NoResourceAllow" {
		t.Error("Reason.String")
	}
}

// The principal keys come from the Caller, never from its ARN, and an
// orphaned session has no aws:PrincipalArn.
func TestCallerContext(t *testing.T) {
	rc := callerContext(
		session,
		map[string][]string{"aws:PrincipalArn": {"arn:aws:iam::1:role/forged"}},
	)
	if v, _ := rc.get("aws:PrincipalArn"); len(v) != 1 || v[0] != session.PrincipalARN {
		t.Errorf("session aws:PrincipalArn = %v", v)
	}
	for key, want := range map[string]string{
		"aws:PrincipalAccount": acct, "aws:userid": session.UserID, "aws:PrincipalType": "AssumedRole",
	} {
		if v, _ := rc.get(key); len(v) != 1 || v[0] != want {
			t.Errorf("session %s = %v, want %s", key, v, want)
		}
	}
}

func TestCallerContextAbsentKeys(t *testing.T) {
	rc := callerContext(orphan, map[string][]string{"aws:PrincipalArn": {orphan.ARN}})
	if v, ok := rc.get("aws:PrincipalArn"); ok {
		t.Errorf("orphan aws:PrincipalArn = %v, want absent", v)
	}
	rc = callerContext(Caller{ARN: devUser.ARN}, nil)
	for _, key := range []string{"aws:PrincipalArn", "aws:PrincipalAccount", "aws:userid", "aws:PrincipalType"} {
		if v, ok := rc.get(key); ok {
			t.Errorf("empty caller %s = %v, want absent", key, v)
		}
	}
	if v, _ := rc.get("aws:username"); len(v) != 1 || v[0] != "dev" {
		t.Errorf("aws:username = %v", v)
	}
}

func TestAuthorizeStatementOrder(t *testing.T) {
	p := mustParseResource(t, `{"Version":"2012-10-17","Statement":[`+
		`{"Sid":"Acct","Effect":"Allow","Principal":{"AWS":"`+acct+`"},"Action":"s3:GetObject","Resource":"*"},`+
		`{"Sid":"Dev","Effect":"Allow","Principal":{"AWS":"`+devUser.ARN+`"},"Action":"s3:GetObject","Resource":"*"}]}`)
	got := Authorize(AuthorizeRequest{
		Action:          "s3:GetObject",
		Resource:        "arn:aws:s3:::b/k",
		ResourceAccount: acct,
		Caller:          devUser,
	}, p)
	want := Authorization{
		Decision: Allow, Identity: Result{Decision: ImplicitDeny, Policy: -1},
		Resource: Result{Decision: Allow, Policy: 0, Sid: "Dev"}, Direct: true,
	}
	if got != want {
		t.Fatalf("Authorize = %+v, want %+v", got, want)
	}
}

// Statements of the wrong kind never apply: a resource-based policy's
// statement needs a Principal and a Resource, and an identity policy's
// statement must have no Principal.
func TestAuthorizeIgnoresOtherKinds(t *testing.T) {
	trust := mustParse(t, trustDoc(`"*"`))
	lenient := mustParse(t, allowAll)
	req := AuthorizeRequest{
		Action:          "sts:AssumeRole",
		Resource:        "*",
		ResourceAccount: acct,
		Caller:          devUser,
	}
	if got := Authorize(
		req,
		trust,
	); got.Decision != ImplicitDeny ||
		got.Resource.Decision != ImplicitDeny {
		t.Errorf("trust policy as resource policy: %+v", got)
	}
	if got := Authorize(req, lenient); got.Resource.Decision != ImplicitDeny {
		t.Errorf("identity policy as resource policy: %+v", got)
	}
	if got := Authorize(req, nil, trust); got.Identity.Decision != ImplicitDeny {
		t.Errorf("trust policy as identity policy: %+v", got)
	}
}
