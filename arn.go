package policy

import (
	"strings"
	"unicode/utf8"
)

// arn is an ARN split into its six colon-separated fields:
// arn:partition:service:region:account-id:resource. The resource field keeps
// any further colons ("Identify AWS resources with Amazon Resource Names
// (ARNs)", https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html).
type arn struct {
	partition, service, region, account, resource string
}

func parseARN(s string) (arn, bool) {
	f := strings.SplitN(s, ":", 6)
	if len(f) != 6 || f[0] != "arn" {
		return arn{}, false
	}
	return arn{partition: f[1], service: f[2], region: f[3], account: f[4], resource: f[5]}, true
}

func (a arn) isRoot() bool { return a.service == "iam" && a.resource == "root" }

// assumedRole returns the role name of an assumed-role session ARN,
// arn:partition:sts::account:assumed-role/role-name/role-session-name
// ("AWS JSON policy elements: Principal", role session principals,
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html).
func (a arn) assumedRole() (string, bool) {
	if a.service != "sts" {
		return "", false
	}
	rest, ok := strings.CutPrefix(a.resource, "assumed-role/")
	if !ok {
		return "", false
	}
	name, _, ok := strings.Cut(rest, "/")
	return name, ok && name != ""
}

// roleName returns the name of an IAM role ARN,
// arn:partition:iam::account:role/path/role-name.
func (a arn) roleName() (string, bool) {
	if a.service != "iam" || !strings.HasPrefix(a.resource, "role/") {
		return "", false
	}
	return a.resource[strings.LastIndexByte(a.resource, '/')+1:], true
}

// principalARN is the value of aws:PrincipalArn for a caller with this ARN:
// the role's ARN for a role session, the ARN itself otherwise.
func (a arn) principalARN() (string, bool) {
	if name, ok := a.assumedRole(); ok {
		return "arn:" + a.partition + ":iam::" + a.account + ":role/" + name, true
	}
	return a.String(), true
}

func (a arn) String() string {
	return "arn:" + a.partition + ":" + a.service + ":" + a.region + ":" + a.account + ":" + a.resource
}

// resourcePattern compiles a Resource or NotResource entry.
//
// Wildcards follow "IAM JSON policy elements: Resource"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html):
// "You can use wildcard characters (* and ?) within the individual segments
// of an ARN (the parts separated by colons)" and "If the * wildcard is the
// last character of a resource ARN segment, it can expand to match beyond
// the colon boundaries." So in the first five fields a "*" stays inside its
// field unless it ends the field, and "?" never matches a colon. In the
// resource field, which may itself hold colons, "*" matches anything and "?"
// any one character. "*" alone therefore matches every resource.
//
// An ARN with fewer than six fields is completed with "*" fields: "When you
// specify an incomplete ARN (one with fewer than the standard six fields) in
// an identity-based policy, AWS automatically completes the ARN by adding
// wildcard characters (*) to all missing fields." (IAM User Guide, "Grammar
// of the IAM JSON policy language",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html).
//
// Policy variables are replaced only in the resource field: "You can use a
// policy variable in the Resource element, but only in the resource portion
// of the ARN. This portion of the ARN appears after the fifth colon (:)."
// ("IAM policy elements: Variables and tags"). A variable elsewhere is kept
// as literal text. The second result is false when a variable has no value:
// "the resource that includes a policy variable with no value will not
// match any resource" (same page).
func resourcePattern(raw string, vars bool, c *requestContext) (pattern, bool) {
	prefix, rest, colons := splitResource(raw, vars)
	hasRest := colons == 5
	if !hasRest && strings.HasPrefix(raw, "arn:") {
		prefix += strings.Repeat(":*", 4-colons) + ":"
		rest, hasRest = "*", true
	}
	p := make(pattern, 0, len(raw))
	for i := 0; i < len(prefix); {
		r, n := utf8.DecodeRuneInString(prefix[i:])
		i += n
		p = p.add(prefixToken(r, i == len(prefix) || prefix[i] == ':'))
	}
	if !hasRest {
		return p, true
	}
	return expand(p, rest, vars, c)
}

// prefixToken compiles a rune of the first five fields of a Resource ARN;
// last reports whether it ends its field.
func prefixToken(r rune, last bool) token {
	switch {
	case r == '*' && last:
		return token{kind: tokStar}
	case r == '*':
		return token{kind: tokStarInSegment}
	case r == '?':
		return token{kind: tokAnyInSegment}
	default:
		return token{kind: tokLit, r: r}
	}
}

// splitResource splits a Resource entry after its fifth colon, not counting
// colons inside a ${...} variable. With fewer than five, prefix is all of
// raw and colons is how many it has.
func splitResource(raw string, vars bool) (prefix, rest string, colons int) {
	for i := 0; i < len(raw); i++ {
		if vars && strings.HasPrefix(raw[i:], "${") {
			if end := strings.IndexByte(raw[i:], '}'); end > 0 {
				i += end
				continue
			}
		}
		if raw[i] != ':' {
			continue
		}
		colons++
		if colons == 5 {
			return raw[:i+1], raw[i+1:], colons
		}
	}
	return raw, "", colons
}

// arnFields compiles an ArnEquals/ArnLike policy value into one pattern per
// ARN field. "Each of the six colon-delimited components of the ARN is
// checked separately and each can include multi-character match wildcards
// (*) or single-character match wildcards (?)." (IAM User Guide, "IAM JSON
// policy elements: Condition operators",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html).
// ok is false when the value, after its variables are replaced, has fewer
// than six fields.
func arnFields(p pattern) ([6]pattern, bool) {
	var f [6]pattern
	n := 0
	for _, t := range p {
		if n < 5 && t.kind == tokLit && t.r == ':' {
			n++
			continue
		}
		f[n] = f[n].add(t)
	}
	return f, n == 5
}

// matchARNFields reports whether the six field patterns match the ARN v
// field by field.
func matchARNFields(f [6]pattern, v string) bool {
	parts := strings.SplitN(v, ":", 6)
	if len(parts) != 6 {
		return false
	}
	for i, part := range parts {
		if !f[i].match(part, false) {
			return false
		}
	}
	return true
}
