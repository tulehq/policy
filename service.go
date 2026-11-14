package policy

import (
	"slices"
	"strings"
)

// Requests made by AWS service principals follow "AWS JSON policy
// elements: Principal" (AWS service principals, All principals,
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html),
// "AWS JSON policy elements: NotPrincipal"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html)
// and "AWS global condition context keys"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html).

// ServiceRequest is one request made by an AWS service principal, such as
// secretsmanager.amazonaws.com, to authorize with AuthorizeService.
//
//nolint:govet // fieldalignment: the field order is the published API.
type ServiceRequest struct {
	// Action is the action requested, such as "lambda:InvokeFunction".
	Action string
	// Resource is the ARN of the resource the action is on.
	Resource string
	// Service is the service principal that makes the request, such as
	// "secretsmanager.amazonaws.com": "A service principal is an
	// identifier for a service." (Principal page).
	Service string
	// Context holds the request's condition context keys and their values,
	// as in Request, such as aws:SourceArn and aws:SourceAccount, which
	// "The calling service passes" ("AWS global condition context keys").
	// The keys that come from the principal replace any value Context
	// gives them (see serviceContext).
	Context map[string][]string
	// Unknown names context keys whose values could not be determined, as
	// in Request. It applies to the keys that come from the principal too.
	Unknown []string
}

// AuthorizeService decides req against the resource's resource-based
// policy alone: a service principal has no identity-based policies.
// Parse the policy with ParseResource; nil means the resource has none.
//
// A statement applies when its Action or NotAction and its Resource or
// NotResource match, its Principal names req.Service (see
// principals.serviceMatch) or its NotPrincipal does not exclude it (see
// principals.excludesService), and all of its conditions hold, with the
// condition, variable and Unknown handling of Authorize. A statement
// without a Principal or NotPrincipal, or without a Resource or
// NotResource, never applies. Then, as in Authorize: "If the enforcement
// code finds even one explicit deny that applies, the enforcement code
// returns a final decision of Deny." ("Policy evaluation logic",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html).
// So:
//
//   - a Deny that applies denies, with ExplicitDeny and ResourceDeny;
//   - else an Allow that applies allows, and Direct is true: the grant
//     names the service itself, not an account;
//   - else the request is denied with ImplicitDeny and NoResourceAllow.
//
// Resource is the policy's result, as in Authorize. Identity is always an
// ImplicitDeny Result with Policy -1: there are no identity-based policies
// to evaluate, and the resource-based policy alone decides.
//
// A nil policy, and a req.Service that is not a valid Service value of a
// Principal element (the rule ParseResource applies: a dotted name that is
// not an ARN, without wildcards), are denied with ImplicitDeny and
// NoResourceAllow before any statement is read.
func AuthorizeService(req ServiceRequest, resource *Policy) Authorization {
	none := Result{Decision: ImplicitDeny, Policy: -1}
	out := Authorization{
		Decision: ImplicitDeny,
		Reason:   NoResourceAllow,
		Identity: none,
		Resource: none,
	}
	if resource == nil || !validPrincipalID("Service", req.Service, true) {
		return out
	}
	rc := serviceContext(req.Service, req.Context).
		withUnknown(append(slices.Clip(req.Unknown), serviceUnknownKeys...))
	out.Resource, _ = evaluateResource(resource, func(s *statement, vars bool) (matchKind, bool) {
		return s.grantsService(req.Action, req.Resource, req.Service, vars, rc)
	})
	switch out.Resource.Decision {
	case ExplicitDeny:
		out.Decision, out.Reason = ExplicitDeny, ResourceDeny
	case Allow:
		out.Decision, out.Reason, out.Direct = Allow, NoReason, true
	}
	return out
}

// serviceUnknownKeys are the principal keys whose value for a service
// principal AWS does not document though it says they are present.
// "aws:PrincipalArn ... This key is included in the request context for
// all signed requests", and aws:PrincipalAccount, aws:PrincipalType and
// aws:userid are "included in the request context for all requests,
// including anonymous requests" ("AWS global condition context keys"), yet
// neither that page nor the principal table of "IAM policy elements:
// Variables and tags" gives their value for a service principal. A key
// that is present with a value that cannot be determined is what Unknown
// means here, so they are unknown whatever Context gives them: a condition
// on one never helps an Allow apply and always helps a Deny apply. This is
// this package's choice, the one that fails closed.
var serviceUnknownKeys = []string{
	"aws:PrincipalArn",
	"aws:PrincipalAccount",
	"aws:PrincipalType",
	"aws:userid",
}

// serviceContext is the request context for the service principal
// service: ctx, with the keys that come from the principal taken from it,
// whatever ctx gives them ("AWS global condition context keys"):
//
//   - aws:PrincipalServiceName is service: "This key is present in the
//     request when the call is made by an AWS service principal" and
//     "contains the name of the service principal".
//   - aws:PrincipalIsAWSService is "true": "The request context key is set
//     to true when a service uses a service principal to perform a direct
//     action on your resources."
//   - aws:username, aws:PrincipalOrgID, aws:PrincipalOrgPaths and every
//     aws:PrincipalTag/ key are absent. aws:username "is always included in
//     the request context for IAM users", which a service is not; the org
//     keys are "included in the request context only if the principal is a
//     member of an organization", and the tag keys "if the principal is
//     using an IAM user with attached tags" or "an IAM role with attached
//     tags or session tags", neither of which a service principal is.
//
// aws:PrincipalArn, aws:PrincipalAccount, aws:PrincipalType and aws:userid
// are unknown (see serviceUnknownKeys). aws:PrincipalServiceNamesList comes
// from ctx only, as every other key does: it "contains an unordered list of
// all service principal names associated with the Regional instance of the
// service", which service alone does not give (the Principal page shows
// one service under a regional and a non-regional name), and AWS lists no
// example value. A caller that cannot tell its values passes it in
// Unknown.
func serviceContext(service string, ctx map[string][]string) *requestContext {
	rc := newRequestContext("", ctx)
	for k := range rc.values {
		if strings.HasPrefix(k, "aws:principaltag/") {
			delete(rc.values, k)
		}
	}
	rc.values["aws:principalservicename"] = []string{service}
	rc.values["aws:principalisawsservice"] = []string{"true"}
	for _, k := range []string{"aws:username", "aws:principalorgid", "aws:principalorgpaths"} {
		// Present with no values: absent, and not derived (see get).
		rc.values[k] = []string{}
	}
	return rc
}

// grantsService reports whether a resource-based statement applies to a
// request made by the service principal service, and how its Principal
// named it (matchNone under NotPrincipal).
func (s *statement) grantsService(
	action, resource, service string,
	vars bool,
	rc *requestContext,
) (matchKind, bool) {
	if s.principal == nil || !s.matchesAction(action) || !s.matchesResource(resource, vars, rc) {
		return matchNone, false
	}
	kind := matchDirect
	if s.notPrincipal {
		if s.principal.excludesService(service) {
			return matchNone, false
		}
		kind = matchNone
	} else if !s.principal.serviceMatch(service) {
		return matchNone, false
	}
	return kind, s.conditionsHold(vars, rc)
}

// serviceMatch reports whether a resource-based policy's Principal or
// NotPrincipal element names the service principal service:
//
//   - A Service value equal to service names it. Values compare exactly,
//     as TrustMatch compares them; a regional name such as
//     "s3.ap-east-1.amazonaws.com" is another value than
//     "s3.amazonaws.com" ("You must use the regionalized service principal
//     name when an AWS service in an opt-in Region makes a request to
//     another Region."; Principal page), and which name a request carries
//     is the caller's to say.
//   - "*" and {"AWS":"*"} name it, in an Allow as in a Deny. The SNS
//     Developer Guide gives a queue policy with "Principal": "*" and an
//     aws:SourceArn condition as "an example policy statement that allows
//     the Amazon SNS topic to send a message to the Amazon SQS queue"
//     (https://docs.aws.amazon.com/sns/latest/dg/sns-send-message-to-sqs-cross-account.html),
//     and uses {"AWS":"*"} the same way
//     (https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html).
//     S3's RestrictPublicBuckets "restricts access to an access point or
//     bucket with a public policy to only AWS service principals and
//     authorized users within the bucket owner's account", so a public
//     policy reaches service principals
//     (https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html).
//     For a Deny, the NotPrincipal page uses "Principal": "*" "to prevent
//     all service principals, except those specified in the Condition
//     element, from accessing or manipulating your resources".
//
// AWS, CanonicalUser and Federated values never name a service principal.
func (p *principals) serviceMatch(service string) bool {
	return p.all || slices.Contains(p.byType["Service"], service)
}

// excludesService reports whether a NotPrincipal element exempts the
// service principal service from its Deny statement: "The NotPrincipal
// element uses "Effect":"Deny" to deny access to all principals except
// the principal specified in the NotPrincipal element. A principal can be
// ... AWS service, or other principal type." (NotPrincipal page). It does
// when the element names the service (see serviceMatch): by a Service
// value equal to service, or by "*" or {"AWS":"*"}, as principals.excludes
// exempts every caller for "*" in Authorize.
func (p *principals) excludesService(service string) bool {
	return p.serviceMatch(service)
}
