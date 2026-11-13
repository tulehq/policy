package policy_test

// Conformance rows for unknown context keys (Request.Unknown). AWS has no
// such notion: its request context always knows whether a key is present.
// Each row cites the AWS rule for an absent key or a variable with no value
// that an unknown key would otherwise fall under, and is marked "CHOICE:":
// this package resolves an unknown key against the caller instead, so that
// a key the service could not determine never grants and always denies.

import (
	"testing"

	"tule.dev/policy"
)

const cfOrg = "aws:PrincipalOrgID"

// cfUnknown is one request with unknown keys against a policy, which is
// evaluated alone (want ImplicitDeny or Allow) or, for a Deny, after
// cfAllowAll (want ExplicitDeny or Allow).
//
//nolint:govet // fieldalignment: field order reads as the table rows do.
type cfUnknown struct {
	name    string
	src     string
	stated  string
	policy  string
	res     string
	ctx     cfCtx
	unknown []string
	want    policy.Decision
}

func cfUnknownAllow(cond string) string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*",` +
		`"Condition":` + cond + `}}`
}

func cfUnknownDeny(cond string) string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*",` +
		`"Condition":` + cond + `}}`
}

var cfUnknownCases = []cfUnknown{
	{
		name: "Allow StringNotEquals on an unknown key",
		src:  docCondition,
		stated: "If the policy condition requires that the key is not matched, such as StringNotLike " +
			"or ArnNotLike, and the right key is not present, the condition is true. " +
			"CHOICE: an unknown key is not absent; the Allow does not apply",
		policy:  cfUnknownAllow(`{"StringNotEquals":{"aws:PrincipalOrgID":"o-bad"}}`),
		unknown: []string{cfOrg},
		want:    policy.ImplicitDeny,
	},
	{
		name: "Deny StringEquals on an unknown key",
		src:  docCondition,
		stated: "If the key that you specify in a policy condition is not present in the request " +
			"context, the values do not match and the condition is false. " +
			"CHOICE: an unknown key is not absent; the Deny applies",
		policy:  cfUnknownDeny(`{"StringEquals":{"aws:PrincipalOrgID":"o-bad"}}`),
		unknown: []string{cfOrg},
		want:    policy.ExplicitDeny,
	},
	{
		name: "Deny StringNotEquals on an unknown key that Context also gives",
		src:  docCondition,
		stated: "CHOICE: the key is unknown whatever Context gives it; the Deny applies " +
			"although the given value would not match it",
		policy:  cfUnknownDeny(`{"StringNotEquals":{"aws:PrincipalOrgID":"o-good"}}`),
		ctx:     cfCtx{cfOrg: {"o-good"}},
		unknown: []string{"AWS:PRINCIPALORGID"},
		want:    policy.ExplicitDeny,
	},
	{
		name: "Allow StringEqualsIfExists on an unknown key",
		src:  docOperators,
		stated: "If the key is not present, evaluate the condition element as true. " +
			"CHOICE: an unknown key is not absent; the Allow does not apply",
		policy:  cfUnknownAllow(`{"StringEqualsIfExists":{"aws:PrincipalOrgID":"o-good"}}`),
		unknown: []string{cfOrg},
		want:    policy.ImplicitDeny,
	},
	{
		name: "Deny StringNotEqualsIfExists on an unknown key",
		src:  docOperators,
		stated: "CHOICE: an unknown key is not absent, and the Deny applies " +
			"whether or not a known value would match",
		policy:  cfUnknownDeny(`{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":"o-good"}}`),
		unknown: []string{cfOrg},
		want:    policy.ExplicitDeny,
	},
	{
		name: "Allow Null true on an unknown key",
		src:  docOperators,
		stated: "use either true (the key doesn't exist — it is null) or false. " +
			"CHOICE: an unknown key is neither; the Allow does not apply",
		policy:  cfUnknownAllow(`{"Null":{"aws:PrincipalOrgID":"true"}}`),
		unknown: []string{cfOrg},
		want:    policy.ImplicitDeny,
	},
	{
		name:    "Allow Null false on an unknown key",
		src:     docOperators,
		stated:  "CHOICE: an unknown key is not known to exist; the Allow does not apply",
		policy:  cfUnknownAllow(`{"Null":{"aws:PrincipalOrgID":"false"}}`),
		unknown: []string{cfOrg},
		want:    policy.ImplicitDeny,
	},
	{
		name:    "Deny Null false on an unknown key",
		src:     docOperators,
		stated:  "CHOICE: an unknown key is not known to be null; the Deny applies",
		policy:  cfUnknownDeny(`{"Null":{"aws:PrincipalOrgID":"false"}}`),
		unknown: []string{cfOrg},
		want:    policy.ExplicitDeny,
	},
	{
		name: "Allow ForAllValues on an unknown key",
		src:  docSetOps,
		stated: "ForAllValues ... also returns true if there are no context keys in the request. " +
			"CHOICE: an unknown key may hold any values; the Allow does not apply",
		policy:  cfUnknownAllow(`{"ForAllValues:StringEquals":{"aws:TagKeys":["env"]}}`),
		unknown: []string{"aws:TagKeys"},
		want:    policy.ImplicitDeny,
	},
	{
		name: "Deny ForAnyValue on an unknown key",
		src:  docSetOps,
		stated: "ForAnyValue ... returns false if the key does not exist. " +
			"CHOICE: an unknown key may hold the value; the Deny applies",
		policy:  cfUnknownDeny(`{"ForAnyValue:StringEquals":{"aws:TagKeys":["secret"]}}`),
		unknown: []string{"aws:TagKeys"},
		want:    policy.ExplicitDeny,
	},
	{
		name: "Allow Resource with a variable naming an unknown key",
		src:  docVariables,
		stated: "the resource that includes a policy variable with no value will not match any " +
			"resource. CHOICE: an unknown variable does the same in an Allow, whatever other entries say",
		policy: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*",` +
			`"Resource":["arn:aws:s3:::b/${aws:PrincipalOrgID}/*","arn:aws:s3:::b/*"]}}`,
		res:     "arn:aws:s3:::b/o-1/k",
		unknown: []string{cfOrg},
		want:    policy.ImplicitDeny,
	},
	{
		name: "Deny Resource with a variable naming an unknown key",
		src:  docVariables,
		stated: "the resource that includes a policy variable with no value will not match any " +
			"resource. CHOICE: an unknown variable matches every resource in a Deny",
		policy: `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*",` +
			`"Resource":"arn:aws:s3:::b/${aws:PrincipalOrgID}/*"}}`,
		res:     "arn:aws:s3:::elsewhere/k",
		unknown: []string{cfOrg},
		want:    policy.ExplicitDeny,
	},
	{
		name: "Allow StringNotEquals with a variable naming an unknown key",
		src:  docVariables,
		stated: "Inverted condition operators like StringNotEquals or StringNotLike do match " +
			"against a null value. CHOICE: an unknown variable is not a null value; the Allow does not apply",
		policy:  cfUnknownAllow(`{"StringNotEquals":{"s3:prefix":"${aws:PrincipalOrgID}"}}`),
		ctx:     cfCtx{"s3:prefix": {"o-1"}},
		unknown: []string{cfOrg},
		want:    policy.ImplicitDeny,
	},
	{
		name: "Deny StringEquals with a variable naming an unknown key",
		src:  docVariables,
		stated: "condition operators like StringEquals or StringLike do not match, and the policy " +
			"statement does not take effect. CHOICE: an unknown variable may match; the Deny applies",
		policy:  cfUnknownDeny(`{"StringEquals":{"s3:prefix":"${aws:PrincipalOrgID, 'none'}"}}`),
		ctx:     cfCtx{"s3:prefix": {"o-1"}},
		unknown: []string{cfOrg},
		want:    policy.ExplicitDeny,
	},
	{
		name:    "An unknown key the policy does not test changes nothing",
		src:     docCondition,
		stated:  "CHOICE: only conditions and variables that use an unknown key are affected",
		policy:  cfUnknownAllow(`{"StringEquals":{"aws:username":"Bob"}}`),
		unknown: []string{cfOrg},
		want:    policy.Allow,
	},
}

func TestConformanceUnknownKeys(t *testing.T) {
	allowAll := cfParse(t, cfAllowAll)
	for _, c := range cfUnknownCases {
		t.Run(c.name, func(t *testing.T) {
			p := cfParse(t, c.policy)
			pols := []*policy.Policy{p}
			if c.want == policy.ExplicitDeny {
				pols = []*policy.Policy{allowAll, p}
			}
			req := policy.Request{
				Action:    "s3:GetObject",
				Resource:  or(c.res, "arn:aws:s3:::b/k"),
				Principal: cfUser,
				Context:   c.ctx,
				Unknown:   c.unknown,
			}
			if r := policy.Evaluate(req, pols...); r.Decision != c.want {
				t.Errorf("Decision = %v, want %v\n  unknown: %v ctx=%v\n  source: %s\n  stated: %s",
					r.Decision, c.want, c.unknown, c.ctx, c.src, c.stated)
			}
		})
	}
}
