package policy

import (
	"fmt"
	"testing"
)

// mustParse parses doc or fails the test.
func mustParse(t testing.TB, doc string) *Policy {
	t.Helper()
	p, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse(%s): %v", doc, err)
	}
	return p
}

// ctx builds a request context from key, value pairs; a key given more
// than once is multivalued.
func ctx(kv ...string) map[string][]string {
	m := map[string][]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = append(m[kv[i]], kv[i+1])
	}
	return m
}

// condPolicy is a policy with one statement of the given effect on every
// action and resource, under the given Condition element.
func condPolicy(effect, condition string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Sid":"S","Effect":%q,`+
		`"Action":"*","Resource":"*","Condition":%s}}`, effect, condition)
}

// anyRequest is a request that condPolicy's statement applies to but for
// its condition.
func anyRequest(c map[string][]string) Request {
	return Request{
		Action:    "s3:GetObject",
		Resource:  "arn:aws:s3:::amzn-s3-demo-bucket/key",
		Principal: "arn:aws:iam::111122223333:user/alice",
		Context:   c,
	}
}

// evalCase is a request against policies and the decision it must get.
//
//nolint:govet // fieldalignment: field order reads as the table rows do.
type evalCase struct {
	name     string
	policies []string
	req      Request
	want     Decision
}

func runEvalCases(t *testing.T, cases []evalCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ps := make([]*Policy, 0, len(c.policies))
			for _, doc := range c.policies {
				ps = append(ps, mustParse(t, doc))
			}
			if got := Evaluate(c.req, ps...); got.Decision != c.want {
				t.Errorf("Evaluate = %+v, want %v", got, c.want)
			}
		})
	}
}

// condCase is a documented condition table row: the Condition element, the
// request context and whether the condition matches.
//
//nolint:govet // fieldalignment: field order reads as the table rows do.
type condCase struct {
	name      string
	condition string
	ctx       map[string][]string
	match     bool
}

// runCondCases runs each row as an Allow statement, which allows the
// request exactly when the condition matches.
func runCondCases(t *testing.T, cases []condCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := mustParse(t, condPolicy("Allow", c.condition))
			want := ImplicitDeny
			if c.match {
				want = Allow
			}
			if got := Evaluate(anyRequest(c.ctx), p); got.Decision != want {
				t.Errorf("Evaluate = %+v, want %v", got, want)
			}
		})
	}
}

// allowAll allows every action on every resource.
const allowAll = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`

func req(action, resource string) Request {
	return Request{
		Action:    action,
		Resource:  resource,
		Principal: "arn:aws:iam::123456789012:user/alice",
	}
}
