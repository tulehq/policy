package policy

import "strings"

// Principal and NotPrincipal follow "AWS JSON policy elements: Principal"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html)
// and "AWS JSON policy elements: NotPrincipal"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html).

// principals is a parsed Principal or NotPrincipal element.
type principals struct {
	// byType maps AWS, Federated, Service and CanonicalUser to their
	// values.
	byType map[string][]string
	// all is "*" or {"AWS": "*"}: "For anonymous users, the following
	// elements are equivalent: "Principal": "*" and "Principal" : { "AWS" :
	// "*" }".
	all bool
}

var principalTypes = map[string]bool{
	"AWS":           true,
	"Federated":     true,
	"Service":       true,
	"CanonicalUser": true,
}

// parsePrincipalElement parses Principal or NotPrincipal:
// ("Principal" | "NotPrincipal") : ("*" | <principal_map>), where each map
// entry is one of "AWS", "Federated", "Service" or "CanonicalUser" with a
// string or an array of strings ("Grammar of the IAM JSON policy
// language"). "You cannot use a wildcard to match part of a principal name
// or ARN." and "The service principal in an IAM policy can't be "Service":
// "*"." (Principal page), so "*" is accepted only as the whole element or
// as an AWS value. "NotPrincipal must be used with "Effect":"Deny". Using
// it with "Effect":"Allow" is not supported." (NotPrincipal page).
func parsePrincipalElement(s *statement, r rawStatement) error {
	v, not, present, err := r.either("Principal", "NotPrincipal")
	if err != nil || !present {
		return err
	}
	if not && s.effect != effectDeny {
		return parseErr(msgNotPrincipalEff)
	}
	p, err := parsePrincipals(v)
	if err != nil {
		return err
	}
	s.principal, s.notPrincipal = p, not
	return nil
}

func parsePrincipals(v any) (*principals, error) {
	if v == "*" {
		return &principals{all: true}, nil
	}
	obj, ok := v.(object)
	if !ok || len(obj) == 0 {
		return nil, parseErr(msgPrincipal)
	}
	p := &principals{byType: map[string][]string{}}
	for _, m := range obj {
		if !principalTypes[m.name] {
			return nil, parseErr(msgPrincipal)
		}
		list, err := stringList(m.value)
		if err != nil || len(list) == 0 {
			return nil, parseErr(msgPrincipal)
		}
		all, ok := checkPrincipalIDs(m.name, list)
		if !ok {
			return nil, parseErr(msgPrincipal)
		}
		p.all = p.all || all
		p.byType[m.name] = list
	}
	return p, nil
}

// checkPrincipalIDs checks the values of one principal type and reports
// whether they include the AWS "*".
func checkPrincipalIDs(typ string, ids []string) (all, ok bool) {
	for _, id := range ids {
		switch {
		case id == "*" && typ == "AWS":
			all = true
		case id == "" || strings.ContainsAny(id, "*?"):
			return false, false
		}
	}
	return all, true
}

// matchKind is how a Principal element names a caller.
type matchKind uint8

const (
	matchNone matchKind = iota
	// matchAccount: only through the caller's account, by an account ID or
	// the account's root ARN.
	matchAccount
	// matchDirect: by "*", or by the caller's own user, role or role
	// session ARN, or service, federated or canonical user identifier.
	matchDirect
)

// matches reports how the element names the caller, the closest match of
// all its values. Values match as follows:
//
//   - "*" matches every caller.
//   - An AWS account ID, or the account's root ARN
//     arn:partition:iam::account-id:root, matches every principal of that
//     account: "The account ARN and the shortened account ID behave the same
//     way. Both delegate permissions to the account. Using the account ARN in
//     the Principal element does not limit permissions to only the root user
//     of the account."
//   - A role ARN matches the role's sessions, whose ARN is
//     arn:partition:sts::account-id:assumed-role/role-name/role-session-name
//     ("When they use those session credentials to perform operations in
//     AWS, they become a role session principal."). A role's name is unique
//     in its account whatever its path, so the role is identified by
//     partition, account and name. It also matches a caller whose context
//     carries that role ARN as aws:PrincipalArn.
//   - Any other value, such as a user, assumed-role session or federated
//     user ARN, or a Service, Federated or CanonicalUser value, matches a
//     caller with exactly that identifier. "In a Principal element, the user
//     name part of the Amazon Resource Name (ARN) is case sensitive."
func (p *principals) matches(caller string, rc *requestContext) matchKind {
	if p.all {
		return matchDirect
	}
	best := matchNone
	for typ, ids := range p.byType {
		for _, id := range ids {
			best = max(best, principalMatch(typ, id, caller, rc))
		}
	}
	return best
}

func principalMatch(typ, id, caller string, rc *requestContext) matchKind {
	switch {
	case typ == "AWS" && (isAccountID(id) || isRootARN(id)):
		if id == caller || awsPrincipalMatches(id, caller, rc) {
			return matchAccount
		}
	case id == caller || typ == "AWS" && awsPrincipalMatches(id, caller, rc):
		return matchDirect
	}
	return matchNone
}

func isRootARN(id string) bool {
	a, ok := parseARN(id)
	return ok && a.isRoot()
}

func awsPrincipalMatches(id, caller string, rc *requestContext) bool {
	c, callerIsARN := parseARN(caller)
	if isAccountID(id) {
		return callerIsARN && c.account == id
	}
	a, ok := parseARN(id)
	switch {
	case !ok || !callerIsARN:
		return false
	case a.isRoot():
		return c.partition == a.partition && c.account == a.account
	default:
		return roleMatches(a, id, c, rc)
	}
}

// roleMatches reports whether the role ARN a (written id) names the caller
// c: one of its sessions, or a caller whose aws:PrincipalArn is id.
func roleMatches(a arn, id string, c arn, rc *requestContext) bool {
	role, ok := a.roleName()
	if !ok {
		return false
	}
	if pa, present := rc.get("aws:PrincipalArn"); present && len(pa) == 1 && pa[0] == id {
		return true
	}
	session, ok := c.assumedRole()
	return ok && session == role && c.partition == a.partition && c.account == a.account
}

// isAccountID reports whether s is a 12-digit AWS account ID ("The ID of
// the AWS account that owns the resource, without the hyphens. For
// example, 123456789012."; "Identify AWS resources with Amazon Resource
// Names (ARNs)").
func isAccountID(s string) bool {
	return len(s) == 12 && digits(s)
}
