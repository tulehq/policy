package policy

import (
	"strconv"
	"strings"
)

// Resource-based policies are evaluated together with identity-based ones
// as the IAM User Guide describes in "How AWS enforcement code logic
// evaluates requests to allow or deny access"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html),
// "Policy evaluation logic"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html),
// "Policy evaluation for requests within a single account"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-basics.html)
// and "Cross-account policy evaluation logic"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html).
// Permissions boundaries, session policies, SCPs and RCPs are not
// evaluated.

// PrincipalType is the kind of principal that makes a request, as AWS
// spells it for the aws:PrincipalType condition key ("AWS global
// condition context keys",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html).
type PrincipalType string

// The principal types a Caller can have.
const (
	// PrincipalTypeAccount is an account's root user.
	PrincipalTypeAccount PrincipalType = "Account"
	// PrincipalTypeUser is an IAM user.
	PrincipalTypeUser PrincipalType = "User"
	// PrincipalTypeAssumedRole is a role session.
	PrincipalTypeAssumedRole PrincipalType = "AssumedRole"
)

// Caller describes the principal that makes a request, for Authorize.
//
//nolint:govet // fieldalignment: the field order is the published API.
type Caller struct {
	// AccountID is the caller's 12-digit account ID.
	AccountID string
	// ARN is the ARN of the identity that signed: an IAM user's ARN, the
	// account's root ARN (arn:aws:iam::<account>:root), or the session's
	// assumed-role ARN (arn:aws:sts::<account>:assumed-role/<role>/<session>).
	ARN string
	// PrincipalARN is the value of aws:PrincipalArn: ARN for a user or the
	// root user, and the role's ARN, path included, for a role session.
	// For a role session an empty PrincipalARN means the session's role
	// no longer exists: nothing that names the role then matches the
	// caller, and aws:PrincipalArn is absent.
	PrincipalARN string
	// UserID is the value of aws:userid: an IAM user's unique ID (AIDA...),
	// the account ID for the root user, and <role ID>:<session name> for
	// a role session, the role ID being the role's unique ID (AROA...).
	UserID string
	// Type is the value of aws:PrincipalType. A caller of any other type
	// matches only "*" and account principals.
	Type PrincipalType
}

// orphaned reports whether c is a session whose role no longer exists.
func (c Caller) orphaned() bool {
	return c.Type == PrincipalTypeAssumedRole && c.PrincipalARN == ""
}

// Reason is why Authorize denied a request, in the terms of AWS's
// AccessDenied messages ("Troubleshoot access denied error messages",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html).
type Reason int

const (
	// NoReason is the Reason of an Allow.
	NoReason Reason = iota
	// IdentityDeny is a Deny statement in an identity-based policy that
	// applies.
	IdentityDeny
	// ResourceDeny is a Deny statement in the resource-based policy that
	// applies.
	ResourceDeny
	// NoIdentityAllow is an identity-based Allow that is needed and that
	// no statement gives.
	NoIdentityAllow
	// NoResourceAllow is a resource-based Allow that is needed and that no
	// statement gives.
	NoResourceAllow
)

func (r Reason) String() string {
	switch r {
	case NoReason:
		return "NoReason"
	case IdentityDeny:
		return "IdentityDeny"
	case ResourceDeny:
		return "ResourceDeny"
	case NoIdentityAllow:
		return "NoIdentityAllow"
	case NoResourceAllow:
		return "NoResourceAllow"
	default:
		return "Reason(" + strconv.Itoa(int(r)) + ")"
	}
}

// Message is the phrase AWS ends its AccessDenied message with for r and
// action, such as "with an explicit deny in a resource-based policy" or
// "because no identity-based policy allows the s3:GetObject action": "AWS
// includes the phrase with an explicit deny in a <type> policy" and
// "because no <type> policy allows the <action> action" ("Troubleshoot
// access denied error messages"). It is empty for NoReason and for an
// unknown Reason.
func (r Reason) Message(action string) string {
	switch r {
	case IdentityDeny:
		return "with an explicit deny in an identity-based policy"
	case ResourceDeny:
		return "with an explicit deny in a resource-based policy"
	case NoIdentityAllow:
		return "because no identity-based policy allows the " + action + " action"
	case NoResourceAllow:
		return "because no resource-based policy allows the " + action + " action"
	default:
		return ""
	}
}

// AuthorizeRequest is one request to authorize with Authorize.
//
//nolint:govet // fieldalignment: the field order is the published API.
type AuthorizeRequest struct {
	// Action is the action requested, such as "s3:GetObject".
	Action string
	// Resource is the ARN of the resource the action is on.
	Resource string
	// ResourceAccount is the 12-digit ID of the account that owns the
	// resource.
	ResourceAccount string
	// Caller is the principal that makes the request.
	Caller Caller
	// Context holds the request's condition context keys and their values,
	// as in Request. aws:PrincipalArn, aws:PrincipalAccount, aws:userid and
	// aws:PrincipalType come from Caller and replace any value Context
	// gives them; each is absent when its Caller field is empty.
	Context map[string][]string
}

// Authorization is Authorize's decision and why it was made.
//
//nolint:govet // fieldalignment: the field order is the published API.
type Authorization struct {
	// Decision is Allow, ExplicitDeny or ImplicitDeny.
	Decision Decision
	// Reason is NoReason for an Allow, else why the request is denied.
	Reason Reason
	// Identity is the identity-based policies' result, as from Evaluate:
	// Policy indexes the identity policies passed to Authorize. For a root
	// user caller without an applying Deny it is Allow with Policy -1.
	Identity Result
	// Resource is the resource-based policy's result: Policy is 0 for a
	// deciding statement in it, else -1.
	Resource Result
	// Direct is true for a resource-based Allow that names the caller
	// other than through its account: by "*", its user, role or session
	// ARN, or its unique ID. A resource-based Allow that names the caller
	// only by its account ID or root ARN is not direct.
	Direct bool
}

// Authorize decides req against the caller's identity-based policies
// (nil ones are skipped) and the resource's resource-based policy
// (resource, nil when the resource has none), as AWS does within one
// account and across accounts. Parse the policies with ParseIdentity and
// ParseResource. It applies, in order:
//
//  1. An identity-based Deny that applies denies (IdentityDeny), then a
//     resource-based one (ResourceDeny): "If the enforcement code finds
//     even one explicit deny that applies, the enforcement code returns a
//     final decision of Deny." AWS names one policy type when several
//     deny ("AWS includes only one of those policy types in the error
//     message"); which one it names is not documented, and naming the
//     identity-based one first is this package's choice.
//  2. The caller is in the resource's account (Caller.AccountID equals
//     ResourceAccount): an identity-based Allow allows ("If either the
//     identity-based policy or the resource-based policy within the same
//     account allows the request and the other doesn't, the request is
//     still allowed."), and so does a direct resource-based Allow. A
//     resource-based Allow that names the caller only through its account
//     "delegates authority to the account" ("AWS JSON policy elements:
//     Principal"), and the same-account exception covers only grants "if
//     the specified principal is an IAM user, an IAM role, or a session
//     principal", so it also needs an identity-based Allow. Otherwise the
//     request is denied with NoIdentityAllow; that AWS names the
//     identity-based policy type here is this package's choice.
//  3. The caller is in another account: "The request is allowed only if
//     both evaluations return a decision of Allow", so an identity-based
//     Allow (else NoIdentityAllow) and a resource-based Allow of any kind
//     (else NoResourceAllow) are both needed.
//
// A root user caller (PrincipalTypeAccount) has an identity-based Allow
// without policies: "all requests are implicitly denied with the exception
// of the AWS account root user, which has full access". Authorize applies
// no other root rule: a service that never evaluates its own account's
// root user keeps doing so before calling it.
//
// A resource-based statement applies when its Action or NotAction and its
// Resource or NotResource match, its Principal names the caller (see
// Caller and principals.callerMatch) or its NotPrincipal does not exclude
// it (see principals.excludes), and all of its conditions hold. A
// statement without a Principal or NotPrincipal, or without a Resource or
// NotResource, never applies.
func Authorize(req AuthorizeRequest, resource *Policy, identity ...*Policy) Authorization {
	rc := callerContext(req.Caller, req.Context)
	id := evaluateIdentity(req.Action, req.Resource, rc, identity)
	if req.Caller.Type == PrincipalTypeAccount && id.Decision == ImplicitDeny {
		id = Result{Decision: Allow, Policy: -1}
	}
	res, direct := evaluateResource(req.Action, req.Resource, req.Caller, rc, resource)
	out := Authorization{Identity: id, Resource: res, Direct: direct}
	out.Decision, out.Reason = decide(id.Decision, res.Decision, direct,
		isAccountID(req.Caller.AccountID) && req.Caller.AccountID == req.ResourceAccount)
	return out
}

// decide combines the identity-based decision id and the resource-based
// decision res (direct when res is a direct Allow), within one account
// (same) or across accounts, as Authorize describes.
func decide(id, res Decision, direct, same bool) (Decision, Reason) {
	switch {
	case id == ExplicitDeny:
		return ExplicitDeny, IdentityDeny
	case res == ExplicitDeny:
		return ExplicitDeny, ResourceDeny
	default:
		return decideAllow(id == Allow, res == Allow, direct, same)
	}
}

// decideAllow is decide when no Deny applies, given whether the identity
// and the resource-based policies allow.
func decideAllow(idAllow, resAllow, direct, same bool) (Decision, Reason) {
	switch {
	case same && (idAllow || resAllow && direct):
		return Allow, NoReason
	case !idAllow:
		return ImplicitDeny, NoIdentityAllow
	case !same && !resAllow:
		return ImplicitDeny, NoResourceAllow
	default:
		return Allow, NoReason
	}
}

// callerContext is the request context for c: ctx, with aws:PrincipalArn,
// aws:PrincipalAccount, aws:userid and aws:PrincipalType taken from c.
// An empty field makes its key absent, and an absent key is never derived
// from c.ARN, so an orphaned session (see Caller.PrincipalARN) has no
// aws:PrincipalArn. aws:username is derived from c.ARN for a user when
// ctx lacks it, as in Evaluate.
func callerContext(c Caller, ctx map[string][]string) *requestContext {
	rc := newRequestContext(c.ARN, ctx)
	for key, v := range map[string]string{
		"aws:principalarn":     c.PrincipalARN,
		"aws:principalaccount": c.AccountID,
		"aws:userid":           c.UserID,
		"aws:principaltype":    string(c.Type),
	} {
		if v == "" {
			// Present with no values: absent, and not derived (see get).
			rc.values[key] = []string{}
			continue
		}
		rc.values[key] = []string{v}
	}
	return rc
}

// evaluateResource decides the resource-based policy p for caller: the
// first Deny that applies, else the first direct Allow, else the first
// Allow, and whether that Allow is direct. A nil p decides ImplicitDeny.
func evaluateResource(
	action, resource string,
	caller Caller,
	rc *requestContext,
	p *Policy,
) (Result, bool) {
	res, direct := Result{Decision: ImplicitDeny, Policy: -1}, false
	if p == nil {
		return res, false
	}
	for _, s := range p.statements {
		kind, applies := s.grants(action, resource, caller, p.vars, rc)
		if !applies {
			continue
		}
		if s.effect == effectDeny {
			return Result{Decision: ExplicitDeny, Policy: 0, Sid: s.sid}, false
		}
		d := kind == matchDirect
		if res.Decision == ImplicitDeny || d && !direct {
			res, direct = Result{Decision: Allow, Policy: 0, Sid: s.sid}, d
		}
	}
	return res, direct
}

// grants reports whether a resource-based statement applies to the
// request, and how its Principal named the caller (matchNone under
// NotPrincipal).
func (s *statement) grants(
	action, resource string,
	caller Caller,
	vars bool,
	rc *requestContext,
) (matchKind, bool) {
	if s.principal == nil || !s.matchesAction(action) || !s.matchesResource(resource, vars, rc) {
		return matchNone, false
	}
	kind := matchNone
	if s.notPrincipal {
		if s.principal.excludes(caller) {
			return matchNone, false
		}
	} else if kind = s.principal.callerMatch(caller); kind == matchNone {
		return matchNone, false
	}
	return kind, s.conditionsHold(vars, rc)
}

// callerMatch reports how a resource-based policy's Principal element
// names the caller, the closest match of all its values ("AWS JSON policy
// elements: Principal",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html).
// Values match as follows; names in ARNs match case-sensitively ("the
// user name part of the ARN is case sensitive"), and by ARN rather than
// by the unique ID AWS stores (see the README's known gaps).
//
//   - "*" or {"AWS":"*"} matches every caller, directly: "using a wildcard
//     (*) with an Allow effect grants access to all users, including
//     anonymous users (public access). For IAM users and role principals
//     within your account, no other permissions are required."
//   - An account ID, or arn:partition:iam::account:root, matches every
//     caller of that account (for the root ARN, also of that partition)
//     through the account: "The account ARN and the shortened account ID
//     behave the same way. Both delegate permissions to the account."
//   - A user ARN matches the IAM user (Type User) with that ARN.
//   - A role ARN matches a session of the role (Type AssumedRole) whose
//     PrincipalARN is that ARN, path included: "You can specify the role
//     ARN in the Principal element ... the principal that makes the
//     request is the IAM role session." ("How AWS enforcement code logic
//     evaluates requests to allow or deny access").
//   - An assumed-role session ARN matches the session with that ARN.
//   - A user unique ID (AIDA...) matches the IAM user with that UserID, and a
//     role unique ID (AROA...) a session of that role, whose UserID is
//     <role ID>:<session name> ("IAM identifiers").
//   - Nothing that names a role (a role ARN, a session ARN, a role unique
//     ID) matches an orphaned session, whose role no longer exists.
//   - Service, CanonicalUser and Federated values, federated-user session
//     ARNs and other ARNs match no caller: no Caller is a service, a
//     canonical user or a federated user.
func (p *principals) callerMatch(c Caller) matchKind {
	if p.all {
		return matchDirect
	}
	best := matchNone
	for _, id := range p.byType["AWS"] {
		best = max(best, awsCallerMatch(id, c))
	}
	return best
}

func awsCallerMatch(id string, c Caller) matchKind {
	switch {
	case isAccountID(id):
		return kindIf(c.AccountID == id, matchAccount)
	case isUniqueID(id):
		return kindIf(uniqueIDMatches(id, c), matchDirect)
	}
	a, ok := parseARN(id)
	switch {
	case !ok:
		return matchNone
	case a.isRoot():
		ca, ok := parseARN(c.ARN)
		return kindIf(ok && ca.partition == a.partition && a.account == c.AccountID, matchAccount)
	default:
		return kindIf(identityARNMatches(a, id, c), matchDirect)
	}
}

// kindIf is kind when cond holds, else matchNone.
func kindIf(cond bool, kind matchKind) matchKind {
	if cond {
		return kind
	}
	return matchNone
}

// identityARNMatches reports whether the user, role or session ARN id
// (parsed as a) names the caller itself.
func identityARNMatches(a arn, id string, c Caller) bool {
	if a.service == "iam" && strings.HasPrefix(a.resource, "user/") {
		return c.Type == PrincipalTypeUser && c.ARN == id
	}
	if c.Type != PrincipalTypeAssumedRole || c.orphaned() {
		return false
	}
	if a.service == "iam" && strings.HasPrefix(a.resource, "role/") {
		return c.PrincipalARN == id
	}
	_, isSession := a.assumedRole()
	return isSession && c.ARN == id
}

func uniqueIDMatches(id string, c Caller) bool {
	if strings.HasPrefix(id, userIDPrefix) {
		return c.Type == PrincipalTypeUser && c.UserID == id
	}
	return c.Type == PrincipalTypeAssumedRole && !c.orphaned() &&
		strings.HasPrefix(c.UserID, id+":")
}

// excludes reports whether a NotPrincipal element exempts the caller from
// its Deny statement. "When you use NotPrincipal, you must also specify
// the account ARN of the not-denied principal. Otherwise, the policy might
// deny access to the entire account containing the principal. ... AWS
// might validate the account first, then the role, and then the
// assumed-role user. ... we strongly recommend that you explicitly include
// the ARN for a user's account, or include both the ARN for a role and the
// ARN for the account containing that role." ("AWS JSON policy elements:
// NotPrincipal",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html).
// AWS leaves the exact rule to each service ("might"); this package's
// choice, the strict reading, is that the caller is exempt only when the
// element names its account (by account ID or root ARN) and, unless the
// caller is the root user, the caller itself as Principal would (its user
// ARN or ID, or its role's ARN or ID or its session ARN), or when the
// element is "*". An orphaned session is never named itself, so it is
// never exempt unless by "*".
func (p *principals) excludes(c Caller) bool {
	if p.all {
		return true
	}
	account, direct := false, false
	for _, id := range p.byType["AWS"] {
		kind := awsCallerMatch(id, c)
		account = account || kind == matchAccount
		direct = direct || kind == matchDirect
	}
	return account && (direct || c.Type == PrincipalTypeAccount)
}
