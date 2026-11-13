package policy

import "strings"

// The shapes of IAM and STS identifiers, from "IAM identifiers"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html)
// and the IAM and STS API references: a user or role name matches
// [\w+=,.@-]+ (UserName and RoleName in
// https://docs.aws.amazon.com/IAM/latest/APIReference/API_User.html and
// API_Role.html), a path is "/" or "/" [\u0021-\u007E]+ "/" (Path,
// same pages), and a role session name matches [\w+=,.@-]* (RoleSessionName,
// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).

// isIAMName reports whether s is a non-empty IAM user, role, role session
// or federated user name.
func isIAMName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		if !isAlnum(c) && !strings.ContainsRune("_+=,.@-", rune(c)) {
			return false
		}
	}
	return true
}

// isPathName reports whether the resource field of an IAM user or role
// ARN has the form kind + path + name, with kind "user/" or "role/": the
// entity's path, IAM's pathType (/) | (/[\u0021-\u007E]+/), with its
// leading "/" taken by kind, then a valid name. So "user/bob" (path "/")
// and "user/a//b/bob" (path "/a//b/") have the form, and "user//bob"
// (path "//") does not. A path may hold any printable ASCII, "${", "*" and
// "?" included; a policy principal refuses those separately (see
// validPrincipalID and isResourcePrincipalARN).
func isPathName(resource, kind string) bool {
	rest, ok := strings.CutPrefix(resource, kind)
	if !ok {
		return false
	}
	i := strings.LastIndexByte(rest, '/')
	path := rest[:i+1]
	if path == "/" {
		return false
	}
	for _, c := range []byte(path) {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return isIAMName(rest[i+1:])
}

// sessionNames splits the resource field of an assumed-role ARN,
// assumed-role/role-name/role-session-name.
func sessionNames(resource string) (role, session string, ok bool) {
	rest, ok := strings.CutPrefix(resource, "assumed-role/")
	if !ok {
		return "", "", false
	}
	role, session, ok = strings.Cut(rest, "/")
	return role, session, ok && isIAMName(role) && isIAMName(session)
}

// isPartition reports whether s has the form of a partition, such as aws
// or aws-cn ("If you have resources in other partitions, the partition is
// aws-partitionname."; "IAM identifiers").
func isPartition(s string) bool {
	return s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}

// iamARN parses an IAM or STS ARN with a valid partition, a blank region
// and a 12-digit account.
func iamARN(s string) (arn, bool) {
	a, ok := parseARN(s)
	return a, ok && isPartition(a.partition) && a.region == "" && isAccountID(a.account) &&
		(a.service == "iam" || a.service == "sts")
}

// isResourcePrincipalARN reports whether id is an ARN that an AWS
// principal of a resource-based policy may be ("AWS JSON policy elements:
// Principal"): an account root ARN, arn:partition:iam::account:root; a
// user ARN, arn:partition:iam::account:user/path/name; a role ARN,
// arn:partition:iam::account:role/path/name; a role session ARN,
// arn:partition:sts::account:assumed-role/role-name/role-session-name;
// or a federated user ARN, arn:partition:sts::account:federated-user/name
// ("You can specify federated user sessions in the Principal element of a
// resource-based policy"). Anything else is refused, a group among them:
// "You cannot identify a user group as a principal in a policy (such as a
// resource-based policy)".
//
// A policy variable is refused too: variables are replaced only in the
// elements "IAM policy elements: Variables and tags" lists, which do not
// include Principal, so "${" could only be literal path text that names
// no principal a policy author means.
func isResourcePrincipalARN(id string) bool {
	a, ok := iamARN(id)
	if !ok || strings.Contains(id, "${") {
		return false
	}
	if a.service == "iam" {
		return a.resource == "root" || isPathName(a.resource, "user/") ||
			isPathName(a.resource, "role/")
	}
	_, _, session := sessionNames(a.resource)
	name, federated := strings.CutPrefix(a.resource, "federated-user/")
	return session || federated && isIAMName(name)
}
