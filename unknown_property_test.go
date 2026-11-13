package policy

import (
	"encoding/json"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// The keys the property test's policies test. propKnown is always given
// in Context; the others are the ones marked unknown and assigned values.
const (
	propA     = "k:a"
	propOrg   = "aws:PrincipalOrgID"
	propTag   = "aws:PrincipalTag/team"
	propKnown = "k:b"
)

// propUnknowns are the Unknown lists tried, with the keys each covers.
var propUnknowns = []struct {
	names []string
	keys  []string
}{
	{[]string{propA}, []string{propA}},
	{[]string{"AWS:PRINCIPALORGID"}, []string{propOrg}},
	{[]string{"aws:PrincipalTag/"}, []string{propTag}},
	{[]string{propTag}, []string{propTag}},
	{[]string{propA, "aws:principaltag/"}, []string{propA, propTag}},
	{[]string{propA, propOrg, "aws:PrincipalTag/"}, []string{propA, propOrg, propTag}},
}

// propValues are the request values assigned to unknown keys: every value
// of unknownOperands, and values the policy variables and resources use.
func propValues() []string {
	seen := map[string]bool{"": true, "o-1": true, "x": true}
	for _, o := range unknownOperands {
		seen[o.hit], seen[o.miss] = true, true
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

// propResources are Resource and NotResource entries, some with variables
// naming the unknown keys. The request's resource is propObject.
var propResources = []string{
	"*",
	"arn:aws:s3:::b/*",
	"arn:aws:s3:::c/*",
	"arn:aws:s3:::b/${k:a}/*",
	"arn:aws:s3:::b/${aws:PrincipalOrgID}/k",
	"arn:aws:s3:::b/${aws:PrincipalTag/team, 'x'}/*",
}

const propObject = "arn:aws:s3:::b/x/k"

// propGen builds random policies.
type propGen struct {
	r   *rand.Rand
	ops []string
}

func (g *propGen) pick(xs []string) string { return xs[g.r.IntN(len(xs))] }

// conditions is a Condition element of up to two operators, or "".
func (g *propGen) conditions() string {
	n := g.r.IntN(3)
	if n == 0 {
		return ""
	}
	cond := map[string]map[string]string{}
	for len(cond) < n {
		name := g.pick(g.ops)
		op, _ := parseOperator(name)
		key := g.pick([]string{propA, propOrg, propTag, propKnown})
		var v string
		switch {
		case op.base.kind == kindNull:
			v = g.pick([]string{"true", "false"})
		case op.base.vars() && op.base.kind != kindBool && op.base.kind != kindARN && g.r.IntN(3) == 0:
			v = g.pick([]string{"${k:a}", "${aws:PrincipalOrgID}", "${aws:PrincipalTag/team, 'x'}"})
		default:
			v = unknownOperands[op.base.kind].policy
		}
		cond[name] = map[string]string{key: v}
	}
	b, _ := json.Marshal(cond)
	return `,"Condition":` + string(b)
}

func (g *propGen) resources() string {
	el := "Resource"
	if g.r.IntN(3) == 0 {
		el = "NotResource"
	}
	entries := []string{g.pick(propResources)}
	if g.r.IntN(2) == 0 {
		entries = append(entries, g.pick(propResources))
	}
	b, _ := json.Marshal(entries)
	return `,"` + el + `":` + string(b)
}

func (g *propGen) effect() string { return g.pick([]string{"Allow", "Deny"}) }

func (g *propGen) doc(statement func(effect string) string) string {
	n := 1 + g.r.IntN(3)
	ss := make([]string, n)
	for i := range ss {
		ss[i] = statement(g.effect())
	}
	return `{"Version":"2012-10-17","Statement":[` + strings.Join(ss, ",") + `]}`
}

func (g *propGen) identity() string {
	return g.doc(func(effect string) string {
		return `{"Effect":"` + effect + `","Action":"` + g.pick(
			[]string{"*", "s3:GetObject", "s3:Put*"},
		) +
			`"` + g.resources() + g.conditions() + `}`
	})
}

// propPrincipals name devUser and session in each way a Principal can:
// directly, through their account, or not at all.
var propPrincipals = []string{
	`"*"`,
	`{"AWS":"` + acct + `"}`,
	`{"AWS":"` + devUser.ARN + `"}`,
	`{"AWS":"` + session.PrincipalARN + `"}`,
	`{"AWS":"` + other + `"}`,
}

// propNotPrincipals exempt devUser, session, both or neither.
var propNotPrincipals = []string{
	`{"AWS":["` + devUser.ARN + `","` + acct + `"]}`,
	`{"AWS":["` + session.PrincipalARN + `","` + acct + `"]}`,
	`{"AWS":"` + acct + `"}`,
	`{"AWS":"` + other + `"}`,
}

func (g *propGen) resource() string {
	return g.doc(func(effect string) string {
		principal := `"Principal":` + g.pick(propPrincipals)
		if effect == "Deny" && g.r.IntN(2) == 0 {
			principal = `"NotPrincipal":` + g.pick(propNotPrincipals)
		}
		return `{"Effect":"` + effect + `",` + principal + `,"Action":"s3:GetObject"` +
			g.resources() + g.conditions() + `}`
	})
}

func (g *propGen) trust() string {
	return g.doc(func(effect string) string {
		p := g.pick(append(slices.Clone(propPrincipals), `{"AWS":"`+session.ARN+`"}`))
		return `{"Effect":"` + effect + `","Principal":` + p + `,"Action":"` +
			g.pick([]string{"sts:AssumeRole", "*"}) + `"` + g.conditions() + `}`
	})
}

// assignment is the request context with propKnown's value known, and
// each of keys given no values (absent), one value or two.
func (g *propGen) assignment(known string, keys, values []string) map[string][]string {
	c := map[string][]string{propKnown: {known}}
	for _, k := range keys {
		switch g.r.IntN(4) {
		case 0:
		case 1, 2:
			c[k] = []string{g.pick(values)}
		default:
			c[k] = []string{g.pick(values), g.pick(values)}
		}
	}
	return c
}

// propOutcome is everything a decision gives the caller, ranked: the
// decision first (see rank), then Direct.
func propOutcome(d Decision, direct bool) int {
	r := rank(d) * 2
	if direct {
		r++
	}
	return r
}

// The worst-over-values property: whatever the policies, a result with
// unknown keys is no better for the caller, Direct included, than the
// result for any values those keys could have. Random identity, trust
// and resource policies (with NotPrincipal) are checked against random
// assignments of absent, single and multiple values.
func TestUnknownWorstOverValues(t *testing.T) {
	const cases, assignments = 3000, 12
	// A fixed seed keeps the cases the same from run to run.
	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // test data, not security
	g := &propGen{r: r, ops: unknownOperators()}
	slices.Sort(g.ops)
	values := propValues()
	for i := range cases {
		id, rp, tp := g.identity(), g.resource(), g.trust()
		ip := mustParseKind(t, id, ParseIdentity)
		rpp := mustParseKind(t, rp, ParseResource)
		tpp := mustParseKind(t, tp, ParseTrust)
		u := propUnknowns[g.r.IntN(len(propUnknowns))]
		caller := []Caller{devUser, session}[g.r.IntN(2)]
		resAccount := []string{acct, other}[g.r.IntN(2)]
		known := g.pick(values)
		base := g.assignment(known, u.keys, values)

		outcomes := func(c map[string][]string, unknown []string) [3]int {
			ev := Evaluate(Request{
				Action: "s3:GetObject", Resource: propObject, Principal: caller.ARN,
				Context: c, Unknown: unknown,
			}, ip)
			az := Authorize(AuthorizeRequest{
				Action: "s3:GetObject", Resource: propObject, ResourceAccount: resAccount,
				Caller: caller, Context: c, Unknown: unknown,
			}, rpp, ip)
			tr := EvaluateTrust(tpp, TrustRequest{
				RoleAccount: acct, Action: "sts:AssumeRole", Principal: caller.ARN,
				Context: c, Unknown: unknown,
			})
			return [3]int{
				propOutcome(ev.Decision, false),
				propOutcome(az.Decision, az.Direct),
				propOutcome(tr.Decision, tr.Direct),
			}
		}
		got := outcomes(base, u.names)
		for range assignments {
			c := g.assignment(known, u.keys, values)
			want := outcomes(c, nil)
			for j, name := range []string{"Evaluate", "Authorize", "EvaluateTrust"} {
				if got[j] > want[j] {
					t.Fatalf("case %d: %s with %v unknown ranks %d, above %d for %v\n"+
						"  caller %s, resource account %s\n  identity %s\n  resource %s\n  trust %s",
						i, name, u.names, got[j], want[j], c, caller.ARN, resAccount, id, rp, tp)
				}
			}
		}
	}
}

func mustParseKind(t *testing.T, doc string, parse func([]byte) (*Policy, error)) *Policy {
	t.Helper()
	p, err := parse([]byte(doc))
	if err != nil {
		t.Fatalf("generated policy %s: %v", doc, err)
	}
	return p
}
