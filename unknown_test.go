package policy

import (
	"fmt"
	"strings"
	"testing"
)

// unknownOperands is one valid policy value per base operator family, with
// a request value that matches it and one that does not.
var unknownOperands = map[valueKind]struct{ policy, hit, miss string }{
	kindString:     {"x", "x", "y"},
	kindStringFold: {"x", "X", "y"},
	kindStringLike: {"x*", "xy", "y"},
	kindNumeric:    {"10", "10", "11"},
	kindDate:       {"2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"},
	kindBool:       {"true", "true", "false"},
	kindBinary:     {"QQ==", "QQ==", "Qg=="},
	kindIP:         {"10.0.0.0/8", "10.0.0.1", "192.0.2.1"},
	kindARN: {
		"arn:aws:iam::111122223333:user/a",
		"arn:aws:iam::111122223333:user/a",
		"arn:aws:iam::111122223333:user/b",
	},
}

// unknownOperators is every operator the package accepts: each base
// operator but Null, plain and with IfExists, ForAnyValue and
// ForAllValues in every combination, and Null.
func unknownOperators() []string {
	var ops []string
	for name, b := range baseOps {
		if b.kind == kindNull {
			ops = append(ops, name)
			continue
		}
		for _, set := range []string{"", "ForAnyValue:", "ForAllValues:"} {
			ops = append(ops, set+name, set+name+"IfExists")
		}
	}
	return ops
}

// An unknown key resolves every condition that tests it against the caller:
// an Allow statement never applies and a Deny statement always does,
// whatever the operator and whatever Context holds for the key.
func TestUnknownKeyEveryOperator(t *testing.T) {
	allow := mustParse(t, allowAll)
	for _, name := range unknownOperators() {
		op, ok := parseOperator(name)
		if !ok {
			t.Fatalf("parseOperator(%q) refused", name)
		}
		var values []string
		contexts := map[string]map[string][]string{"absent": nil}
		if op.base.kind == kindNull {
			values = []string{"true", "false"}
			contexts["present"] = ctx("K:V", "x")
		} else {
			o := unknownOperands[op.base.kind]
			values = []string{o.policy}
			contexts["hit"] = ctx("K:V", o.hit)
			contexts["miss"] = ctx("K:V", o.miss)
			contexts["empty"] = ctx("K:V", "")
		}
		for _, v := range values {
			cond := fmt.Sprintf(`{%q:{"k:v":%q}}`, name, v)
			allowP := mustParse(t, condPolicy("Allow", cond))
			denyP := mustParse(t, condPolicy("Deny", cond))
			for cname, c := range contexts {
				r := anyRequest(c)
				r.Unknown = []string{"K:v"}
				if got := Evaluate(r, allowP); got.Decision != ImplicitDeny {
					t.Errorf("%s Allow, %s, unknown: %+v, want ImplicitDeny", cond, cname, got)
				}
				if got := Evaluate(r, allow, denyP); got.Decision != ExplicitDeny {
					t.Errorf("%s Deny, %s, unknown: %+v, want ExplicitDeny", cond, cname, got)
				}
			}
		}
	}
}

// Marking a key unknown changes nothing for a condition on another key,
// and an empty Unknown changes nothing at all. A name ending in "/" marks
// a family, so a family that does not prefix the key changes nothing
// either.
func TestUnknownOtherKeyUnchanged(t *testing.T) {
	allow := mustParse(t, allowAll)
	for _, name := range unknownOperators() {
		op, _ := parseOperator(name)
		v := "true"
		c := ctx("k:v", "x")
		if op.base.kind != kindNull {
			o := unknownOperands[op.base.kind]
			v, c = o.policy, ctx("k:v", o.hit)
		}
		cond := fmt.Sprintf(`{%q:{"k:v":%q}}`, name, v)
		for _, ps := range [][]*Policy{
			{mustParse(t, condPolicy("Allow", cond))},
			{allow, mustParse(t, condPolicy("Deny", cond))},
		} {
			want := Evaluate(anyRequest(c), ps...)
			for _, unknown := range [][]string{{}, {"k:other"}, {"k:v2"}, {"k:v/"}, {"k:"}, {" k:v"}, {"k:v "}, {"k:*"}} {
				r := anyRequest(c)
				r.Unknown = unknown
				if got := Evaluate(r, ps...); got != want {
					t.Errorf("%s unknown %v: %+v, want %+v", cond, unknown, got, want)
				}
			}
		}
	}
}

// unknownVarCase is a policy whose outcome rests on a variable, and the
// decisions with its key unknown.
//
//nolint:govet // fieldalignment: field order reads as the table rows do.
type unknownVarCase struct {
	name     string
	policy   string
	resource string
	ctx      map[string][]string
	want     Decision
}

const orgID = "aws:PrincipalOrgID"

// varDeny is a policy that allows everything and has one Deny statement
// with body.
func varDeny(body string) string {
	return `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"*","Resource":"*"},` +
		`{"Sid":"S","Effect":"Deny","Action":"*",` + body + `}]}`
}

// varAllow is a policy of one Allow statement; body ends the statement.
func varAllow(body string) string {
	return `{"Version":"2012-10-17","Statement":{"Sid":"S","Effect":"Allow","Action":"*",` +
		body + `}`
}

const varObject = "arn:aws:s3:::b/o-1/k"

var varContext = ctx("k:v", "o-1", orgID, "o-1")

// unknownVarCases: a policy variable naming an unknown key resolves
// against the caller, a default value notwithstanding. A condition never
// holds in an Allow and always holds in a Deny. A Resource or NotResource
// entry is dropped or counts as "*", whichever keeps an Allow from
// applying and makes a Deny apply; the other entries match as usual. Variables that are not replaced (outside an ARN's
// resource portion, in a 2008 policy) are literal text and unaffected.
var unknownVarCases = []unknownVarCase{
	{"Allow condition", varAllow(`"Resource":"*",` +
		`"Condition":{"StringEquals":{"k:v":"${aws:PrincipalOrgID}"}}}`), varObject, varContext, ImplicitDeny},
	{"Allow negated condition", varAllow(`"Resource":"*",` +
		`"Condition":{"StringNotEquals":{"k:v":"${aws:principalorgid}"}}}`), varObject, varContext, ImplicitDeny},
	{"Allow condition with default", varAllow(`"Resource":"*",` +
		`"Condition":{"StringLike":{"k:v":"${aws:PrincipalOrgID, 'o-1'}"}}}`), varObject, varContext, ImplicitDeny},
	{"Allow condition one of two values", varAllow(`"Resource":"*",` +
		`"Condition":{"StringEquals":{"k:v":["o-1","${aws:PrincipalOrgID}"]}}}`), varObject, varContext, ImplicitDeny},
	{
		"Allow ARN condition", varAllow(`"Resource":"*",` +
			`"Condition":{"ArnLike":{"k:a":"arn:aws:iam::${aws:PrincipalOrgID}:*"}}}`),
		varObject, ctx("k:a", "arn:aws:iam::o-1:user/a"), ImplicitDeny,
	},
	{"Allow Bool condition", varAllow(`"Resource":"*",` +
		`"Condition":{"Bool":{"k:b":"${aws:PrincipalOrgID}"}}}`), varObject, ctx("k:b", "true"), ImplicitDeny},
	{"Deny condition", varDeny(`"Resource":"*",` +
		`"Condition":{"StringEquals":{"k:v":"${aws:PrincipalOrgID}"}}`), varObject, ctx("k:v", "o-2"), ExplicitDeny},
	{"Deny negated condition", varDeny(`"Resource":"*",` +
		`"Condition":{"StringNotEquals":{"k:v":"${aws:PrincipalOrgID}"}}`), varObject, varContext, ExplicitDeny},
	{"Deny ForAnyValue condition, key absent", varDeny(`"Resource":"*",` +
		`"Condition":{"ForAnyValue:StringEquals":{"k:v":"${aws:PrincipalOrgID}"}}`), varObject, nil, ExplicitDeny},
	{
		"Allow Resource", varAllow(`"Resource":"arn:aws:s3:::b/${aws:PrincipalOrgID}/*"}`),
		varObject, varContext, ImplicitDeny,
	},
	{
		"Allow Resource, another entry matches", varAllow(
			`"Resource":["arn:aws:s3:::b/${aws:PrincipalOrgID}/*","arn:aws:s3:::b/*"]}`),
		varObject, varContext, Allow,
	},
	{
		"Allow Resource, another entry does not match", varAllow(
			`"Resource":["arn:aws:s3:::b/${aws:PrincipalOrgID}/*","arn:aws:s3:::c/*"]}`),
		varObject, varContext, ImplicitDeny,
	},
	{
		"Allow NotResource, another entry excludes nothing", varAllow(
			`"NotResource":["arn:aws:s3:::b/${aws:PrincipalOrgID}/*","arn:aws:s3:::c/*"]}`),
		"arn:aws:s3:::other/k", varContext, ImplicitDeny,
	},
	{
		"Deny Resource, another entry does not match", varDeny(
			`"Resource":["arn:aws:s3:::c/*","arn:aws:s3:::b/${aws:PrincipalOrgID}/*"]`),
		"arn:aws:s3:::other/k", varContext, ExplicitDeny,
	},
	{
		"Deny NotResource, another entry excludes", varDeny(
			`"NotResource":["arn:aws:s3:::b/${aws:PrincipalOrgID}/*","arn:aws:s3:::b/*"]`),
		varObject, varContext, Allow,
	},
	{
		"Deny NotResource, another entry does not exclude", varDeny(
			`"NotResource":["arn:aws:s3:::b/${aws:PrincipalOrgID}/*","arn:aws:s3:::c/*"]`),
		varObject, varContext, ExplicitDeny,
	},
	{
		"Allow NotResource",
		varAllow(`"NotResource":"arn:aws:s3:::b/${aws:PrincipalOrgID}/*"}`),
		"arn:aws:s3:::other/k",
		varContext,
		ImplicitDeny,
	},
	{
		"Deny Resource", varDeny(`"Resource":"arn:aws:s3:::b/${aws:PrincipalOrgID}/*"`),
		"arn:aws:s3:::other/k", varContext, ExplicitDeny,
	},
	{
		"Deny NotResource", varDeny(`"NotResource":"arn:aws:s3:::b/${aws:PrincipalOrgID}/*"`),
		varObject, varContext, ExplicitDeny,
	},
	{
		"variable in the ARN prefix is literal", varAllow(
			`"Resource":"arn:aws:s3:${aws:PrincipalOrgID}::b/*"}`),
		"arn:aws:s3:${aws:PrincipalOrgID}::b/k", varContext, Allow,
	},
	{
		"2008 policy variable is literal",
		`{"Version":"2008-10-17","Statement":{"Effect":"Allow",` +
			`"Action":"*","Resource":"arn:aws:s3:::b/${aws:PrincipalOrgID}/*"}}`,
		"arn:aws:s3:::b/${aws:PrincipalOrgID}/k",
		varContext,
		Allow,
	},
	{
		"escape variables name no key", varAllow(`"Resource":"arn:aws:s3:::b/${*}/*"}`),
		"arn:aws:s3:::b/*/k", varContext, Allow,
	},
}

func TestUnknownVariable(t *testing.T) {
	for _, c := range unknownVarCases {
		t.Run(c.name, func(t *testing.T) {
			p := mustParse(t, c.policy)
			r := anyRequest(c.ctx)
			r.Resource = c.resource
			r.Unknown = []string{orgID, "*"}
			if got := Evaluate(r, p); got.Decision != c.want {
				t.Errorf("Evaluate = %+v, want %v", got, c.want)
			}
		})
	}
}

// Before any key is unknown, the variable cases above that resolve against
// the caller decide otherwise: the rule is what decides them.
func TestUnknownVariableKnownBaseline(t *testing.T) {
	p := mustParse(t, varAllow(`"Resource":"arn:aws:s3:::b/${aws:PrincipalOrgID}/*"}`))
	r := anyRequest(ctx(orgID, "o-1"))
	r.Resource = "arn:aws:s3:::b/o-1/k"
	if got := Evaluate(r, p); got.Decision != Allow {
		t.Fatalf("known org ID: %+v, want Allow", got)
	}
	r.Unknown = []string{strings.ToUpper(orgID)}
	if got := Evaluate(r, p); got.Decision != ImplicitDeny {
		t.Fatalf("unknown org ID: %+v, want ImplicitDeny", got)
	}
}

// An unknown key overrides what Context gives it and what the principal
// ARN implies.
func TestUnknownOverridesContextAndPrincipal(t *testing.T) {
	p := mustParse(t, condPolicy("Allow", `{"StringEquals":{"aws:username":"alice"}}`))
	r := anyRequest(nil)
	if got := Evaluate(r, p); got.Decision != Allow {
		t.Fatalf("derived aws:username: %+v, want Allow", got)
	}
	r.Unknown = []string{"AWS:USERNAME"}
	if got := Evaluate(r, p); got.Decision != ImplicitDeny {
		t.Fatalf("unknown aws:username: %+v, want ImplicitDeny", got)
	}
	r.Context = ctx("aws:username", "alice")
	if got := Evaluate(r, p); got.Decision != ImplicitDeny {
		t.Fatalf("unknown aws:username in Context: %+v, want ImplicitDeny", got)
	}
}

// A trust policy with the org condition: an unknown org ID never lets the
// caller assume the role, and a Deny on it always applies.
func TestUnknownTrust(t *testing.T) {
	allowOrg := mustParse(t, `{"Version":"2012-10-17","Statement":{"Effect":"Allow",`+
		`"Principal":"*","Action":"sts:AssumeRole",`+
		`"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}}}`)
	denyOutside := mustParse(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
		`"Principal":"*","Action":"sts:AssumeRole"},{"Sid":"D","Effect":"Deny",`+
		`"Principal":"*","Action":"sts:AssumeRole",`+
		`"Condition":{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":"o-1"}}}]}`)
	req := TrustRequest{
		RoleAccount: acct,
		Action:      "sts:AssumeRole",
		Principal:   devUser.ARN,
		Context:     ctx("aws:PrincipalOrgID", "o-1"),
	}
	for _, p := range []*Policy{allowOrg, denyOutside} {
		if got, want := EvaluateTrust(p, req), TrustMatch(
			p, req.RoleAccount, req.Action, req.Principal, req.Context,
		); got != want || got.Decision != Allow {
			t.Fatalf("known: EvaluateTrust %+v, TrustMatch %+v, want both Allow", got, want)
		}
	}
	req.Unknown = []string{"aws:principalorgid"}
	if got := EvaluateTrust(allowOrg, req); got.Decision != ImplicitDeny {
		t.Errorf("Allow on unknown org: %+v, want ImplicitDeny", got)
	}
	if got := EvaluateTrust(denyOutside, req); got.Decision != ExplicitDeny || got.Sid != "D" {
		t.Errorf("Deny on unknown org: %+v, want ExplicitDeny by D", got)
	}
	if got := EvaluateTrust(nil, req); got.Decision != ImplicitDeny {
		t.Errorf("nil trust: %+v, want ImplicitDeny", got)
	}
}

// Authorize applies Unknown to both kinds of policy, and to the keys that
// come from the Caller.
func TestUnknownAuthorize(t *testing.T) {
	rp := mustParseResource(t, resourceDoc("Allow", `"Principal":"*"`, bucketObjects+
		`,"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}`))
	req := AuthorizeRequest{
		Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k", ResourceAccount: other,
		Caller: devUser, Context: ctx("aws:PrincipalOrgID", "o-1"),
	}
	id := mustParse(t, allowAll)
	if got := Authorize(req, rp, id); got.Decision != Allow {
		t.Fatalf("known org: %+v, want Allow", got)
	}
	req.Unknown = []string{"aws:PrincipalOrgID"}
	if got := Authorize(
		req,
		rp,
		id,
	); got.Decision != ImplicitDeny ||
		got.Reason != NoResourceAllow {
		t.Errorf("unknown org: %+v, want ImplicitDeny NoResourceAllow", got)
	}

	denyRole := mustParse(t, `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*",`+
		`"Resource":"*","Condition":{"ArnEquals":{"aws:PrincipalArn":"arn:aws:iam::`+acct+`:role/x"}}}}`)
	req = AuthorizeRequest{
		Action:          "s3:GetObject",
		Resource:        "arn:aws:s3:::b/k",
		ResourceAccount: acct,
		Caller:          devUser,
	}
	if got := Authorize(req, nil, id, denyRole); got.Decision != Allow {
		t.Fatalf("known caller: %+v, want Allow", got)
	}
	req.Unknown = []string{"aws:PrincipalArn"}
	if got := Authorize(req, nil, id, denyRole); got.Decision != ExplicitDeny ||
		got.Reason != IdentityDeny {
		t.Errorf("unknown aws:PrincipalArn: %+v, want ExplicitDeny IdentityDeny", got)
	}
}

// rank orders decisions by how well they serve the caller.
func rank(d Decision) int {
	switch d {
	case ExplicitDeny:
		return 0
	case Allow:
		return 2
	default:
		return 1
	}
}

// checkNoBetter fails when marking keys unknown gave the caller a better
// decision than before.
func checkNoBetter(t *testing.T, what string, before, after Decision) {
	t.Helper()
	if rank(after) > rank(before) {
		t.Fatalf("%s: unknown keys turned %v into %v", what, before, after)
	}
}

// A name ending in "/" marks every key it prefixes, in any case; every
// other name is one exact key, spaces included, and no name is a pattern.
func TestUnknownFamily(t *testing.T) {
	allow := mustParse(t, condPolicy("Allow",
		`{"StringNotEqualsIfExists":{"aws:PrincipalTag/Team":"intern"}}`))
	deny := mustParse(t, condPolicy("Deny", `{"StringEquals":{"aws:PrincipalTag/team":"intern"}}`))
	allowAllP := mustParse(t, allowAll)
	for _, c := range []struct {
		name    string
		unknown []string
		hit     bool
	}{
		{"family", []string{"aws:PrincipalTag/"}, true},
		{"family other case", []string{"AWS:principaltag/"}, true},
		{"shorter family", []string{"aws:"}, false},
		{"shorter family with slash", []string{"aws:Principal/"}, false},
		{"exact key", []string{"aws:principaltag/team"}, true},
		{"leading space", []string{" aws:PrincipalTag/team"}, false},
		{"leading space family", []string{" aws:PrincipalTag/"}, false},
		{"star is not a pattern", []string{"aws:PrincipalTag/*"}, false},
		{"bare prefix without slash", []string{"aws:PrincipalTag"}, false},
		{"other family", []string{"aws:RequestTag/"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := anyRequest(ctx("aws:PrincipalTag/team", "staff"))
			r.Unknown = c.unknown
			wantAllow, wantDeny := Allow, Allow
			if c.hit {
				wantAllow, wantDeny = ImplicitDeny, ExplicitDeny
			}
			if got := Evaluate(r, allow); got.Decision != wantAllow {
				t.Errorf("Allow: %+v, want %v", got, wantAllow)
			}
			if got := Evaluate(r, allowAllP, deny); got.Decision != wantDeny {
				t.Errorf("Deny: %+v, want %v", got, wantDeny)
			}
		})
	}
	// A family also covers variables.
	p := mustParse(t, varAllow(`"Resource":"arn:aws:s3:::b/${aws:PrincipalTag/team}/*"}`))
	r := anyRequest(ctx("aws:PrincipalTag/team", "staff"))
	r.Resource = "arn:aws:s3:::b/staff/k"
	if got := Evaluate(r, p); got.Decision != Allow {
		t.Fatalf("known tag: %+v, want Allow", got)
	}
	r.Unknown = []string{"aws:PrincipalTag/"}
	if got := Evaluate(r, p); got.Decision != ImplicitDeny {
		t.Errorf("unknown tag family in a variable: %+v, want ImplicitDeny", got)
	}
}
