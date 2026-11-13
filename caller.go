package policy

import "strings"

// valid reports whether c's fields agree with one another, as
// tule.dev/sigv4 v0.4.1's Principal defines them: AccountID is a 12-digit
// account ID and the account of ARN, an IAM or STS ARN with a blank
// region, and by Type:
//
//   - Account: ARN is arn:partition:iam::AccountID:root, PrincipalARN is
//     ARN, and UserID is AccountID.
//   - User: ARN is an IAM user ARN, PrincipalARN is ARN, and UserID is a
//     user unique ID (AIDA...).
//   - AssumedRole: ARN is arn:partition:sts::AccountID:assumed-role/name/
//     session; PrincipalARN is empty (the role was deleted) or a role ARN
//     of the same partition and account whose name is name; and UserID is
//     a role unique ID (AROA...), a colon and session.
//
// Any other Type is invalid.
func (c Caller) valid() bool {
	a, ok := iamARN(c.ARN)
	if !ok || a.account != c.AccountID {
		return false
	}
	switch c.Type {
	case PrincipalTypeAccount:
		return a.isRoot() && c.PrincipalARN == c.ARN && c.UserID == c.AccountID
	case PrincipalTypeUser:
		return c.validUser(a)
	case PrincipalTypeAssumedRole:
		return c.validSession(a)
	default:
		return false
	}
}

// validUser is valid for an IAM user whose ARN is a.
func (c Caller) validUser(a arn) bool {
	return a.service == "iam" && isPathName(a.resource, "user/") && c.PrincipalARN == c.ARN &&
		hasIDPrefix(c.UserID, userIDPrefix)
}

// hasIDPrefix reports whether id is a unique ID with prefix.
func hasIDPrefix(id, prefix string) bool {
	return isUniqueID(id) && strings.HasPrefix(id, prefix)
}

// validSession is valid for a role session whose ARN is a.
func (c Caller) validSession(a arn) bool {
	role, session, ok := sessionNames(a.resource)
	if !ok || a.service != "sts" {
		return false
	}
	roleID, userSession, ok := strings.Cut(c.UserID, ":")
	if !ok || userSession != session || !hasIDPrefix(roleID, roleIDPrefix) {
		return false
	}
	return c.PrincipalARN == "" || isRoleOf(c.PrincipalARN, a, role)
}

// isRoleOf reports whether roleARN is the ARN of the role named role in
// the partition and account of the session ARN a.
func isRoleOf(roleARN string, a arn, role string) bool {
	r, ok := iamARN(roleARN)
	if !ok || r.service != "iam" || r.partition != a.partition || r.account != a.account {
		return false
	}
	return isPathName(r.resource, "role/") &&
		r.resource[strings.LastIndexByte(r.resource, '/')+1:] == role
}
