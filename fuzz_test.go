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
