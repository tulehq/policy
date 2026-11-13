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
		case strings.ContainsAny(id, "*?") || !principalIDTypes[typ](id):
			return false, false
		}
	}
	return all, true
}

// principalIDTypes checks that a value has the form of its principal type,
// so that the types stay apart ("AWS JSON policy elements: Principal"):
//
//   - AWS: a 12-digit account ID, or an IAM or STS ARN (account root,
//     user, role, assumed-role session, federated user).
//   - Service: a service principal such as "ecs.amazonaws.com", a dotted
//     name that is not an ARN.
//   - Federated: an IAM SAML or OIDC provider ARN, or a built-in OIDC
//     provider such as "accounts.google.com".
//   - CanonicalUser: a canonical user ID, 64 hexadecimal digits, as in the
//     page's example.
var principalIDTypes = map[string]func(string) bool{
	"AWS": func(id string) bool {
		a, ok := parseARN(id)
		return isAccountID(id) ||
			ok && (a.service == "iam" || a.service == "sts") && a.account != ""
	},
	"Service": isDottedName,
	"Federated": func(id string) bool {
		a, ok := parseARN(id)
		if ok {
			return a.service == "iam" &&
				(strings.HasPrefix(a.resource, "saml-provider/") || strings.HasPrefix(a.resource, "oidc-provider/"))
		}
		return isDottedName(id)
	},
	"CanonicalUser": func(id string) bool {
		return len(id) == 64 && strings.Trim(id, "0123456789abcdef") == ""
	},
}

// isDottedName reports whether id is a dotted host-style name, not an ARN
// or an account ID.
func isDottedName(id string) bool {
	return strings.Contains(id, ".") && !strings.ContainsAny(id, ": ")
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
// all its values. Principals match by ARN, not by the unique ID that IAM
// binds a user or role ARN to when it saves a trust policy, so a recreated
// principal with the same name matches; a caller needing AWS's recreate
// semantics binds ARNs to unique IDs itself. Names in ARNs match
// case-sensitively. Values match as follows:
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
//     partition, account and name. The request context plays no part:
//     a context key such as aws:PrincipalArn does not identify the caller.
//   - Any other value, such as a user, assumed-role session or federated
//     user ARN, or a Service, Federated or CanonicalUser value, matches a
//     caller with exactly that identifier. "In a Principal element, the user
//     name part of the Amazon Resource Name (ARN) is case sensitive."
func (p *principals) matches(caller string) matchKind {
	if p.all {
		return matchDirect
	}
	best := matchNone
	for typ, ids := range p.byType {
		for _, id := range ids {
			best = max(best, principalMatch(typ, id, caller))
		}
	}
	return best
}

func principalMatch(typ, id, caller string) matchKind {
	switch {
	case typ == "AWS" && (isAccountID(id) || isRootARN(id)):
		if id == caller || awsPrincipalMatches(id, caller) {
			return matchAccount
		}
	case id == caller || typ == "AWS" && awsPrincipalMatches(id, caller):
		return matchDirect
	}
	return matchNone
}

func isRootARN(id string) bool {
	a, ok := parseARN(id)
	return ok && a.isRoot()
}

func awsPrincipalMatches(id, caller string) bool {
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
		return roleMatches(a, c)
	}
}

// roleMatches reports whether the role ARN a names the caller c, one of
// its sessions. Only the caller's own ARN identifies it: a request context
// key such as aws:PrincipalArn is the caller's claim, not its identity.
func roleMatches(a, c arn) bool {
	role, ok := a.roleName()
	if !ok {
		return false
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
