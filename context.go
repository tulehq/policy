package policy

import "strings"

// requestContext is a request's context keys, looked up case-insensitively,
// with the principal keys that its principal ARN implies.
type requestContext struct {
	values    map[string][]string
	principal string
}

// newRequestContext indexes ctx by lowercased key. Context key names are not
// case-sensitive ("Context key names are not case-sensitive. For example,
// including the aws:SourceIP context key is equivalent to testing for
// AWS:SourceIp."; IAM User Guide, "IAM JSON policy elements: Condition",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html).
// Keys that differ only by case are one key holding all their values, as
// the same page describes for tag keys that differ only by case.
func newRequestContext(principal string, ctx map[string][]string) *requestContext {
	values := make(map[string][]string, len(ctx))
	for k, v := range ctx {
		lk := strings.ToLower(k)
		values[lk] = append(values[lk], v...)
	}
	return &requestContext{principal: principal, values: values}
}

// get returns the values of key and whether the request carries it. A key
// that Context does not carry may be implied by the principal ARN (see
// principalKey). A key with no values is reported as absent: it is a null
// data set (IAM User Guide, "Single-valued vs. multivalued context keys").
func (c *requestContext) get(key string) ([]string, bool) {
	lk := strings.ToLower(key)
	if v, ok := c.values[lk]; ok {
		return v, len(v) > 0
	}
	if v, ok := principalKey(lk, c.principal); ok {
		return []string{v}, true
	}
	return nil, false
}

// variable returns the value that the policy variable ${name} takes. Only a
// single-valued key can be a variable ("You can use any single-valued
// condition key as a variable. You can't use a multivalued condition key as
// a variable."; IAM User Guide, "IAM policy elements: Variables and tags",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html).
func (c *requestContext) variable(name string) (string, bool) {
	v, ok := c.get(name)
	if !ok || len(v) != 1 {
		return "", false
	}
	return v[0], true
}

// principalKey derives the global keys aws:PrincipalArn,
// aws:PrincipalAccount, aws:username and aws:userid from the caller's ARN,
// for a request whose Context does not carry them. Values follow the
// principal table of the IAM User Guide's "IAM policy elements: Variables
// and tags" page and the key descriptions of "AWS global condition context
// keys" (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html):
//
//   - aws:PrincipalArn: "For IAM roles, the request context returns the ARN
//     of the role, not the ARN of the user that assumed the role." AWS's
//     value is the role ARN with its path. The value derived here from an
//     assumed-role ARN is a fallback without the path, because the session
//     ARN does not carry it, so a path-scoped condition does not apply to
//     it. Callers must pass aws:PrincipalArn in Context for role sessions.
//   - aws:PrincipalAccount: the account field of the ARN.
//   - aws:username: present for IAM users only; the last element of the
//     user's name and path.
//   - aws:userid: the account ID for the account root user. For other
//     principals it is a unique ID that the ARN does not carry, so it comes
//     from Context only.
func principalKey(lowerKey, principal string) (string, bool) {
	a, ok := parseARN(principal)
	if !ok {
		return "", false
	}
	switch lowerKey {
	case "aws:principalaccount":
		return a.account, a.account != ""
	case "aws:principalarn":
		return a.principalARN()
	case "aws:username":
		if a.service == "iam" && strings.HasPrefix(a.resource, "user/") {
			return a.resource[strings.LastIndexByte(a.resource, '/')+1:], true
		}
	case "aws:userid":
		if a.isRoot() {
			return a.account, true
		}
	}
	return "", false
}
