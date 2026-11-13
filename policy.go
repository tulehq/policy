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
// NotResource and all of its conditions match. Principal and NotPrincipal
// are not part of an identity-based policy ("You cannot use the Principal
// element in an identity-based policy."; Principal page) and are ignored
// here; a statement without Resource or NotResource applies to no
// resource.
func Evaluate(req Request, policies ...*Policy) Result {
	rc := newRequestContext(req.Principal, req.Context)
	allow := Result{Decision: ImplicitDeny, Policy: -1}
	for i, p := range policies {
		if p == nil {
			continue
		}
		for _, s := range p.statements {
			if !s.matchesAction(req.Action) || !s.matchesResource(req.Resource, p.vars, rc) ||
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

// AllowsPrincipal reports whether the role trust policy trust lets the
// caller principalARN perform action (such as "sts:AssumeRole") on the
// role it is attached to, given the request's context keys ctx.
//
// A statement applies when its Action or NotAction matches, its Principal
// names the caller (or its NotPrincipal does not), and all of its
// conditions hold; see principals.matches for how values match. A
// statement without a Principal or NotPrincipal applies to no caller, and
// Resource is ignored: a trust policy's resource is the role. As in
// Evaluate, a Deny that applies wins, else an Allow that applies allows.
func AllowsPrincipal(trust *Policy, action, principalARN string, ctx map[string][]string) bool {
	if trust == nil {
		return false
	}
	rc := newRequestContext(principalARN, ctx)
	allowed := false
	for _, s := range trust.statements {
		if !s.trusts(action, principalARN, trust.vars, rc) {
			continue
		}
		if s.effect == effectDeny {
			return false
		}
		allowed = true
	}
	return allowed
}

// trusts reports whether a trust policy statement applies to the caller.
func (s *statement) trusts(action, caller string, vars bool, rc *requestContext) bool {
	return s.principal != nil && s.matchesAction(action) &&
		s.principal.matches(caller, rc) != s.notPrincipal && s.conditionsHold(vars, rc)
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
