package policy

import (
	"errors"
	"testing"
	"unicode/utf8"
)

func FuzzParse(f *testing.F) {
	for _, doc := range parseOK {
		f.Add([]byte(doc))
	}
	for _, c := range parseErrors {
		f.Add([]byte(c.doc))
	}
	f.Add([]byte(carlosPolicy))
	f.Add([]byte(homeDirPolicy))
	f.Fuzz(func(t *testing.T, doc []byte) {
		p, err := Parse(doc)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) || pe.Message == "" {
				t.Fatalf("Parse error %v is not a *ParseError with a message", err)
			}
			return
		}
		if p == nil {
			t.Fatal("Parse returned neither a policy nor an error")
		}
		// A parsed policy must evaluate without panicking.
		Evaluate(anyRequest(ctx("aws:SourceIp", "203.0.113.1")), p)
		AllowsPrincipal(p, "sts:AssumeRole", "arn:aws:iam::123456789012:user/a", nil)
	})
}

// FuzzGlob checks match against the regexp oracle for action and resource
// patterns.
func FuzzGlob(f *testing.F) {
	for _, c := range globCases {
		f.Add(c.pattern, c.s, c.fold)
	}
	for _, c := range resourceCases {
		f.Add(c.pattern, c.resource, false)
	}
	f.Fuzz(func(t *testing.T, pat, s string, fold bool) {
		if !utf8.ValidString(pat) || !utf8.ValidString(s) || len(pat) > 512 || len(s) > 512 {
			return
		}
		p := globPattern(pat)
		if got, want := p.match(s, fold), regexpOf(p, fold).MatchString(s); got != want {
			t.Fatalf("glob %q on %q fold=%v: %v, oracle %v", pat, s, fold, got, want)
		}
		rp, ok := resourcePattern(pat, false, newRequestContext("", nil))
		if !ok {
			t.Fatalf("resourcePattern(%q) unresolved without variables", pat)
		}
		if got, want := rp.match(s, false), regexpOf(rp, false).MatchString(s); got != want {
			t.Fatalf("resource %q on %q: %v, oracle %v", pat, s, got, want)
		}
	})
}

// FuzzEvaluate evaluates arbitrary requests against the documented
// policies and checks the decision's invariants.
func FuzzEvaluate(f *testing.F) {
	f.Add(
		"s3:PutObject",
		"arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar-logs/f",
		carlos,
		"aws:username",
		"x",
	)
	f.Add("s3:GetObject", bucket+"/home/martha_rivera/k", martha, "s3:prefix", "home/")
	f.Add(
		"iam:CreateAccessKey",
		"arn:aws:iam::123456789012:user/a",
		"",
		"aws:SourceIp",
		"203.0.113.9",
	)
	docs := []string{carlosPolicy, homeDirPolicy, allowAll, denyNoMFA, denyPayroll, notActionS3}
	f.Fuzz(func(t *testing.T, action, resource, principal, key, value string) {
		ps := make([]*Policy, 0, len(docs))
		for _, d := range docs {
			ps = append(ps, mustParse(t, d))
		}
		r := Request{
			Action:    action,
			Resource:  resource,
			Principal: principal,
			Context:   ctx(key, value),
		}
		checkResult(t, Evaluate(r, ps...), len(ps))
	})
}

// checkResult checks a decision against policies that include allowAll:
// only an explicit deny can refuse, and the deciding policy is one of them.
func checkResult(t *testing.T, res Result, n int) {
	t.Helper()
	switch res.Decision {
	case Allow, ExplicitDeny:
		if res.Policy < 0 || res.Policy >= n {
			t.Fatalf("decision from policy %d of %d", res.Policy, n)
		}
	default:
		t.Fatalf("decision %+v despite an Allow * statement", res)
	}
}

// FuzzJunkNeverGrants checks that appending a value invalid for the
// operator to a request's key never turns a Deny or an implicit deny into an
// Allow. (A valid appended value may rightly grant, under ForAnyValue.)
func FuzzJunkNeverGrants(f *testing.F) {
	f.Add("10", "ten", 0)
	f.Add("2026-01-01", "9223372036854775807", 4)
	f.Add("10.0.0.1", "nope", 8)
	f.Fuzz(func(t *testing.T, valid, junk string, family int) {
		if family < 0 {
			family = -family
		}
		fam := junkFamilies[family%len(junkFamilies)]
		if !isJunk(fam.name, junk) {
			return
		}
		allow := mustParse(t, condPolicy("Allow", fam.condition))
		deny := mustParse(t, condPolicy("Deny", fam.condition))
		before := ctx("k:v", valid)
		after := ctx("k:v", valid, "k:v", junk)
		for _, ps := range [][]*Policy{{allow}, {allow, deny}} {
			b, a := Evaluate(anyRequest(before), ps...), Evaluate(anyRequest(after), ps...)
			if b.Decision != Allow && a.Decision == Allow {
				t.Fatalf("%s: appending %q turned %v into Allow", fam.name, junk, b.Decision)
			}
		}
	})
}

// isJunk reports whether v is invalid for the named operator. The request
// side accepts exactly the values that checkConditionValue accepts for the
// families in junkFamilies.
func isJunk(operator, v string) bool {
	op, ok := parseOperator(operator)
	return ok && !checkConditionValue(op.base, v, false)
}

func FuzzParseResource(f *testing.F) {
	for _, c := range parseResourceCases {
		f.Add([]byte(c.doc))
	}
	for _, doc := range parseOK {
		f.Add([]byte(doc))
	}
	f.Add([]byte(trustPolicy))
	f.Fuzz(func(t *testing.T, doc []byte) {
		p, err := ParseResource(doc)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) || pe.Message == "" || p != nil {
				t.Fatalf("ParseResource error %v is not a *ParseError with a message alone", err)
			}
			return
		}
		checkResourceStatements(t, p)
		// A parsed policy must authorize consistently, for every kind of
		// caller, within its account and from another.
		for _, c := range []Caller{devUser, session, orphan, root, {}} {
			for _, account := range []string{acct, other} {
				checkAuthorization(t, Authorize(AuthorizeRequest{
					Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k", ResourceAccount: account,
					Caller: c, Context: ctx("aws:SourceIp", "203.0.113.1"),
				}, p), account == c.AccountID)
			}
		}
	})
}

// checkResourceStatements checks that every statement of a policy
// ParseResource accepted has what a resource-based statement needs.
func checkResourceStatements(t *testing.T, p *Policy) {
	t.Helper()
	for i, s := range p.statements {
		if s.principal == nil || !s.hasResource || s.notPrincipal && s.effect != effectDeny {
			t.Fatalf("statement %d is not a resource-based statement: %+v", i, s)
		}
	}
}

// fuzzResourceDocs are resource-based policies whose statements name the
// fuzzed callers in every way a Principal can. Only the first grants
// through "*".
var fuzzResourceDocs = []string{
	resourceDoc("Allow", `"Principal":"*"`, bucketObjects),
	resourceDoc(
		"Allow",
		`"Principal":{"AWS":["`+acct+`","arn:aws:iam::`+other+`:root"]}`,
		bucketObjects,
	),
	resourceDoc("Allow", `"Principal":{"AWS":["`+session.PrincipalARN+`","`+session.ARN+
		`","AROAREADEREXAMPLE0001","`+devUser.ARN+`","AIDADEVEXAMPLE0000001"]}`, bucketObjects),
	resourceDoc("Deny", `"NotPrincipal":{"AWS":["`+devUser.ARN+`","`+acct+`"]}`,
		`,"Resource":"arn:aws:s3:::b/private/*"`),
	resourceDoc("Deny", `"Principal":"*"`, bucketObjects+
		`,"Condition":{"ArnNotEquals":{"aws:PrincipalArn":"`+session.PrincipalARN+`"}}`),
}

const denyAll = `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*"}}`

// FuzzAuthorize authorizes arbitrary callers and requests against
// resource-based policies and checks the decision's invariants.
func FuzzAuthorize(f *testing.F) {
	for _, c := range []Caller{devUser, session, orphan, root} {
		f.Add(c.AccountID, c.ARN, c.PrincipalARN, c.UserID, string(c.Type), acct,
			"s3:GetObject", "arn:aws:s3:::b/k", uint8(2), false)
	}
	f.Add(other, "arn:aws:iam::"+other+":user/x", "arn:aws:iam::"+other+":user/x",
		"AIDAXEXAMPLE000000001", "User", acct, "s3:PutObject",
		"arn:aws:s3:::b/private/k", uint8(3), true)
	f.Fuzz(
		func(t *testing.T, account, arn, principalARN, userID, typ, resAccount, action, resource string,
			doc uint8, idAllow bool,
		) {
			c := Caller{
				AccountID:    account,
				ARN:          arn,
				PrincipalARN: principalARN,
				UserID:       userID,
				Type:         PrincipalType(typ),
			}
			n := int(doc) % len(fuzzResourceDocs)
			rp := mustParseResource(t, fuzzResourceDocs[n])
			var ids []*Policy
			if idAllow {
				ids = append(ids, mustParse(t, allowAll))
			}
			req := AuthorizeRequest{
				Action:          action,
				Resource:        resource,
				ResourceAccount: resAccount,
				Caller:          c,
			}
			got := Authorize(req, rp, ids...)
			if !c.valid() || c.orphaned() {
				checkRefused(t, got)
				return
			}
			checkAuthorization(t, got, account == resAccount)
			if d := Authorize(
				req,
				rp,
				append(ids, mustParse(t, denyAll))...); d.Reason != IdentityDeny {
				t.Fatalf("an identity Deny on everything did not deny: %+v", d)
			}
		},
	)
}

// checkRefused checks that a caller Authorize must refuse before reading
// any policy (an invalid or orphaned one) was refused so.
func checkRefused(t *testing.T, a Authorization) {
	t.Helper()
	none := Result{Decision: ImplicitDeny, Policy: -1}
	if a != (Authorization{Decision: ImplicitDeny, Reason: NoIdentityAllow, Identity: none, Resource: none}) {
		t.Fatalf("an invalid or orphaned caller was evaluated: %+v", a)
	}
}

// checkAuthorization checks the invariants of one Authorize result: the
// reason agrees with the decision and the per-kind results, and an Allow
// has the allows it needs within one account (same) or across accounts.
func checkAuthorization(t *testing.T, a Authorization, same bool) {
	t.Helper()
	if (a.Decision == Allow) != (a.Reason == NoReason) || a.Direct && a.Resource.Decision != Allow {
		t.Fatalf("reason or Direct disagrees with the decision: %+v", a)
	}
	if a.Decision == ExplicitDeny && !explicitDenyFrom(a) {
		t.Fatalf("an explicit deny without its policy's Deny: %+v", a)
	}
	if a.Decision == Allow && !allowedBy(a, same) {
		t.Fatalf("Allow without the allows it needs (same account %v): %+v", same, a)
	}
}

func explicitDenyFrom(a Authorization) bool {
	return a.Reason == IdentityDeny && a.Identity.Decision == ExplicitDeny ||
		a.Reason == ResourceDeny && a.Resource.Decision == ExplicitDeny
}

func allowedBy(a Authorization, same bool) bool {
	id, res := a.Identity.Decision == Allow, a.Resource.Decision == Allow
	if same {
		return id || res && a.Direct
	}
	return id && res
}
