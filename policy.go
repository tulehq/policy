// Package policy parses AWS IAM policy documents and evaluates requests
// against them with the logic AWS applies to identity-based policies within
// one account, and evaluates role trust policies for AssumeRole.
//
// It depends on the standard library only. The rules it implements, and
// the IAM User Guide page each comes from, are cited where they are
// implemented; the README lists them and the known gaps.
package policy

import "strconv"

// Decision is the outcome of evaluating a request.
type Decision int

const (
	// ImplicitDeny means no statement allows the request and none denies
	// it.
	ImplicitDeny Decision = iota
	// Allow means a statement allows the request and none denies it.
	Allow
	// ExplicitDeny means a Deny statement applies to the request.
	ExplicitDeny
)

func (d Decision) String() string {
	switch d {
	case ImplicitDeny:
		return "ImplicitDeny"
	case Allow:
		return "Allow"
	case ExplicitDeny:
		return "ExplicitDeny"
	default:
		return "Decision(" + strconv.Itoa(int(d)) + ")"
	}
}

// Request is one request to authorize.
//
//nolint:govet // fieldalignment: the field order is the published API.
type Request struct {
	// Action is the action requested, such as "s3:GetObject".
	Action string
	// Resource is the ARN of the resource the action is on.
	Resource string
	// Principal is the ARN of the caller. It supplies aws:PrincipalArn,
	// aws:PrincipalAccount, aws:username and (for the account root user)
	// aws:userid when Context does not carry them.
	Principal string
	// Context holds the request's condition context keys and their values.
	// Key names are matched case-insensitively.
	Context map[string][]string
}

// Result is the decision for a request and the statement that made it.
//
//nolint:govet // fieldalignment: the field order is the published API.
type Result struct {
	Decision Decision
	// Policy is the index, among the policies passed to Evaluate, of the
	// policy holding the deciding statement, or -1 for an implicit deny.
	Policy int
	// Sid is the deciding statement's Sid, empty if it has none or for an
	// implicit deny.
	Sid string
}

// Evaluate decides req against the identity-based policies in effect for
// its principal (nil policies are skipped), as AWS does within one
// account:
//
//   - "If the enforcement code finds even one explicit deny that applies,
//     the enforcement code returns a final decision of Deny."
//   - "If there are no identity-based policies or no statements in
//     identity-based policies that allow the requested action, then the
//     request is implicitly denied".
//
// ("How AWS enforcement code logic evaluates requests to allow or deny
// access",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html.)
// The deciding statement is the first Deny that applies, in policy and
// statement order, or else the first Allow.
//
// A statement applies when its Action or NotAction, its Resource or
// NotResource and all of its conditions match. A statement with a
// Principal or NotPrincipal never applies: identity evaluation does not
// honor them, and an identity-based policy cannot have them ("You cannot
// use the Principal element in an identity-based policy."; Principal page),
// so such a statement, which only the lenient Parse accepts, is not an
// identity statement. A statement without Resource or NotResource applies
// to no resource. Parse policies for Evaluate with ParseIdentity.
func Evaluate(req Request, policies ...*Policy) Result {
	rc := newRequestContext(req.Principal, req.Context)
	allow := Result{Decision: ImplicitDeny, Policy: -1}
	for i, p := range policies {
		if p == nil {
			continue
		}
		for _, s := range p.statements {
			if s.principal != nil || !s.matchesAction(req.Action) ||
				!s.matchesResource(req.Resource, p.vars, rc) ||
				!s.conditionsHold(p.vars, rc) {
				continue
			}
			if s.effect == effectDeny {
				return Result{Decision: ExplicitDeny, Policy: i, Sid: s.sid}
			}
			if allow.Decision == ImplicitDeny {
				allow = Result{Decision: Allow, Policy: i, Sid: s.sid}
			}
		}
	}
	return allow
}

// TrustResult is the decision of a role trust policy for one caller.
//
//nolint:govet // fieldalignment: the field order is the published API.
type TrustResult struct {
	Decision Decision
	// Direct is true for an Allow when the caller is a principal of the
	// role's own account and an allowing statement named it other than
	// through its account: by its own user, role or role-session ARN, or
	// by "*". It is false when every allowing statement named the caller
	// only by its account ID or the account's root ARN, for any caller in
	// another account (a cross-account match is never direct), and for a
	// caller without an account in its ARN, such as a service principal.
	Direct bool
	// Sid is the deciding statement's Sid: the Deny that applies, or for
	// an Allow the first direct allowing statement, else the first
	// allowing statement.
	Sid string
}

// TrustMatch evaluates the role trust policy trust, attached to a role in
// the account roleAccount (a 12-digit account ID), for the caller
// principalARN performing action (such as "sts:AssumeRole") on that role,
// given the request's context keys ctx.
//
// A statement applies when its Action or NotAction matches, its Principal
// names the caller (or its NotPrincipal does not), and all of its
// conditions hold; see principals.matches for how values match. Only trust
// statements count: one without a Principal or NotPrincipal, or with a
// Resource or NotResource, never applies, since a trust policy names no
// resource (it is attached to the role). As in Evaluate, a Deny that
// applies wins, else an Allow that applies allows. Parse trust policies
// with ParseTrust.
//
// Direct matters because AWS treats the two kinds of grant differently:
// "If a resource-based policy grants permission directly to the IAM user
// or the session principal that is making the request, then an implicit
// deny in an identity-based policy, a permissions boundary, or a session
// policy does not impact the final decision", while an account principal
// "delegates authority to the account", whose administrator "must then
// grant access to an identity" ("How AWS enforcement code logic evaluates
// requests to allow or deny access",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html,
// and "AWS JSON policy elements: Principal"). So within the account a
// direct Allow suffices, and an account-only Allow also needs an identity
// policy that allows the action. Applying that is the caller's. Direct
// covers only callers in roleAccount, the case "within the same account"
// that the quoted rule describes.
func TrustMatch(
	trust *Policy,
	roleAccount, action, principalARN string,
	ctx map[string][]string,
) TrustResult {
	res := TrustResult{Decision: ImplicitDeny}
	if trust == nil {
		return res
	}
	rc := newRequestContext(principalARN, ctx)
	for _, s := range trust.statements {
		kind, applies := s.trusts(action, principalARN, trust.vars, rc)
		if !applies {
			continue
		}
		if s.effect == effectDeny {
			return TrustResult{Decision: ExplicitDeny, Sid: s.sid}
		}
		direct := kind == matchDirect && sameAccount(principalARN, roleAccount)
		if res.Decision == ImplicitDeny || direct && !res.Direct {
			res = TrustResult{Decision: Allow, Direct: direct, Sid: s.sid}
		}
	}
	return res
}

// AllowsPrincipal reports whether the trust policy allows the caller,
// directly or through its account: TrustMatch's Decision is Allow. The
// role's account matters only to Direct, so none is needed here.
func AllowsPrincipal(trust *Policy, action, principalARN string, ctx map[string][]string) bool {
	return TrustMatch(trust, "", action, principalARN, ctx).Decision == Allow
}

// sameAccount reports whether the caller's ARN is in the account
// roleAccount.
func sameAccount(caller, roleAccount string) bool {
	a, ok := parseARN(caller)
	return ok && isAccountID(roleAccount) && a.account == roleAccount
}

// trusts reports whether a trust policy statement applies to the caller,
// and how its Principal named the caller (matchNone under NotPrincipal).
func (s *statement) trusts(action, caller string, vars bool, rc *requestContext) (matchKind, bool) {
	if s.principal == nil || s.hasResource || !s.matchesAction(action) {
		return matchNone, false
	}
	kind := s.principal.matches(caller)
	if (kind != matchNone) == s.notPrincipal || !s.conditionsHold(vars, rc) {
		return matchNone, false
	}
	if s.notPrincipal {
		return matchNone, true
	}
	return kind, true
}

// matchesAction: action names are case-insensitive ("The prefix and the
// action name are case insensitive. For example, iam:ListAccessKeys is the
// same as IAM:listaccesskeys.") and "You can use multi-character match
// wildcards (*) and single-character match wildcards (?)" ("IAM JSON
// policy elements: Action"). NotAction "explicitly matches everything
// except the specified list of actions" ("IAM JSON policy elements:
// NotAction",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html).
func (s *statement) matchesAction(action string) bool {
	for _, p := range s.actions {
		if p.match(action, true) {
			return !s.notAction
		}
	}
	return s.notAction
}

// matchesResource: Resource matches when any entry matches (see
// resourcePattern). NotResource "explicitly matches every resource except
// those specified" ("IAM JSON policy elements: NotResource",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html).
// Resource ARNs are matched case-sensitively ("In the Resource element,
// the IAM user name is case sensitive."; Resource page). An entry whose
// variable has no value matches no resource, so it excludes none under
// NotResource.
func (s *statement) matchesResource(resource string, vars bool, rc *requestContext) bool {
	if !s.hasResource {
		return false
	}
	for _, raw := range s.resources {
		if p, ok := resourcePattern(raw, vars, rc); ok && p.match(resource, false) {
			return !s.notResource
		}
	}
	return s.notResource
}

// conditionsHold: "If your policy statement has multiple condition
// operators, the condition operators are evaluated using a logical AND. If
// your policy statement has multiple context keys attached to a single
// condition operator, the context keys are evaluated using a logical AND."
// ("Conditions with multiple context keys or values",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-logic-multiple-context-keys-or-values.html).
//
// The statement's effect decides how a malformed request value counts (see
// condition.holds).
func (s *statement) conditionsHold(vars bool, rc *requestContext) bool {
	deny := s.effect == effectDeny
	for _, c := range s.conditions {
		if !c.holds(vars, rc, deny) {
			return false
		}
	}
	return true
}
