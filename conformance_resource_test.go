package policy_test

// Conformance suite for resource-based policies evaluated with Authorize,
// written from AWS documentation only, as conformance_test.go is. Every row
// names the page it comes from and the outcome that page states. Rows whose
// outcome AWS does not state outright are marked "CHOICE:" (this package's
// documented choice) or "ASSUMPTION:" with the reasoning.

import (
	"errors"
	"io/fs"
	"path"
	"strings"
	"testing"

	"tule.dev/policy"
)

const (
	docEvalLogic    = iamDocs + "reference_policies_evaluation-logic.html"
	docCrossAccount = iamDocs + "reference_policies_evaluation-logic-cross-account.html"
	docNotPrincipal = iamDocs + "reference_policies_elements_notprincipal.html"
	docIdentifiers  = iamDocs + "reference_identifiers.html"
	docAccessDenied = iamDocs + "troubleshoot_access-denied.html"
	// srcOrphan is the rule for a session whose role was deleted, as the
	// signing side states it.
	srcOrphan = "tule.dev/sigv4 v0.4.1, keys.go, Principal.PrincipalARN"
	// srcCaller is the definition of the descriptor's fields, which must
	// agree with one another.
	srcCaller = "tule.dev/sigv4 v0.4.1, keys.go, Principal"
)

// Accounts and callers of the rows. Callers carry what sigv4 v0.4.1's
// Principal gives a service: account, ARN, PrincipalARN, UserID and Type.
const (
	rpAcct  = "111122223333"
	rpOther = "444455556666"
)

func rpUser(account, name string) policy.Caller {
	arn := "arn:aws:iam::" + account + ":user/" + name
	return policy.Caller{
		AccountID: account, ARN: arn, PrincipalARN: arn,
		UserID: rpID("AIDA", name), Type: policy.PrincipalTypeUser,
	}
}

// rpID is a unique ID with prefix made from name: its letters and digits,
// upper-cased.
func rpID(prefix, name string) string {
	return prefix + strings.ToUpper(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, name)) + "EXAMPLE000000"
}

// rpSession is a session of the role path+name; path is "" or "p/".
func rpSession(account, path, name, sessionName string) policy.Caller {
	return policy.Caller{
		AccountID:    account,
		ARN:          "arn:aws:sts::" + account + ":assumed-role/" + name + "/" + sessionName,
		PrincipalARN: "arn:aws:iam::" + account + ":role/" + path + name,
		UserID:       rpID("AROA", name) + ":" + sessionName,
		Type:         policy.PrincipalTypeAssumedRole,
	}
}

// rpOrphan is s after its role was deleted: identity supplies an empty
// PrincipalARN (sigv4 v0.4.1 keys.go, Principal.PrincipalARN).
func rpOrphan(s policy.Caller) policy.Caller {
	s.PrincipalARN = ""
	return s
}

func rpRoot(account string) policy.Caller {
	arn := "arn:aws:iam::" + account + ":root"
	return policy.Caller{
		AccountID:    account,
		ARN:          arn,
		PrincipalARN: arn,
		UserID:       account,
		Type:         policy.PrincipalTypeAccount,
	}
}

var (
	rpDev     = rpUser(rpAcct, "dev")
	rpOps     = rpUser(rpAcct, "ops")
	rpPartner = rpUser(rpOther, "partner")
	rpReader  = rpSession(rpAcct, "", "Reader", "s1")
)

const rpObject = "arn:aws:s3:::amzn-s3-demo-bucket/key"

// rpBucket is a bucket policy with one statement: effect, the principal
// element, the actions, and an optional Condition element.
func rpBucket(effect, principal, condition string) string {
	c := ""
	if condition != "" {
		c = `,"Condition":` + condition
	}
	return `{"Version":"2012-10-17","Statement":{"Sid":"Bucket","Effect":"` + effect + `",` + principal +
		`,"Action":"s3:GetObject","Resource":["arn:aws:s3:::amzn-s3-demo-bucket","arn:aws:s3:::amzn-s3-demo-bucket/*"]` +
		c + `}}`
}

const rpAllowGet = `{"Version":"2012-10-17","Statement":{"Sid":"Id","Effect":"Allow",` +
	`"Action":"s3:GetObject","Resource":"*"}}`

const rpDenyGet = `{"Version":"2012-10-17","Statement":{"Sid":"IdDeny","Effect":"Deny",` +
	`"Action":"s3:GetObject","Resource":"*"}}`

// rpCase is one Authorize request. resource and identity entries ending
// in ".json" name files in testdata/aws; others are the documents. An
// empty resource means the resource has no resource-based policy.
//
//nolint:govet // fieldalignment: field order reads as the table rows do.
type rpCase struct {
	name     string
	src      string // AWS page
	stated   string // outcome as AWS states it
	resource string
	identity []string
	caller   policy.Caller
	account  string // the resource's account; rpAcct when empty
	action   string // s3:GetObject when empty
	res      string // rpObject when empty
	ctx      cfCtx
	want     policy.Decision
	reason   policy.Reason
}

func rpLoad(t *testing.T, entry string, parse func([]byte) (*policy.Policy, error)) *policy.Policy {
	t.Helper()
	doc := []byte(entry)
	if strings.HasSuffix(entry, ".json") {
		b, err := fs.ReadFile(cfTestdata, path.Join("aws", entry))
		if err != nil {
			t.Fatalf("read testdata %s: %v", entry, err)
		}
		doc = b
	}
	p, err := parse(doc)
	if err != nil {
		t.Fatalf("parse %s: %v", entry, err)
	}
	return p
}

func rpRun(t *testing.T, cases []rpCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var rp *policy.Policy
			if c.resource != "" {
				rp = rpLoad(t, c.resource, policy.ParseResource)
			}
			ids := make([]*policy.Policy, 0, len(c.identity))
			for _, e := range c.identity {
				ids = append(ids, rpLoad(t, e, policy.ParseIdentity))
			}
			req := policy.AuthorizeRequest{
				Action: or(c.action, "s3:GetObject"), Resource: or(c.res, rpObject),
				ResourceAccount: or(c.account, rpAcct), Caller: c.caller, Context: c.ctx,
			}
			got := policy.Authorize(req, rp, ids...)
			if got.Decision != c.want || got.Reason != c.reason {
				t.Errorf(
					"Authorize = %v, %v; want %v, %v\n  caller: %+v\n  source: %s\n  AWS states: %s",
					got.Decision,
					got.Reason,
					c.want,
					c.reason,
					c.caller,
					c.src,
					c.stated,
				)
			}
		})
	}
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ---------------------------------------------------------------------------
// Within one account

var rpExampleUser = policy.Caller{
	AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:user/carlossalazar",
	PrincipalARN: "arn:aws:iam::123456789012:user/carlossalazar", UserID: "AIDACKCEVSQ6C2EXAMPLE",
	Type: policy.PrincipalTypeUser,
}

var rpSameAccountCases = []rpCase{
	// Source: docEvalBasics, "Example identity-based and resource-based
	// policy evaluation".
	{
		name:     "logs bucket denied by identity",
		src:      docEvalBasics,
		stated:   "the identity-based policy explicitly denies ... access to any S3 buckets used for logging",
		resource: "carlos-bucket.json",
		identity: []string{"carlos-identity.json"},
		caller:   rpExampleUser,
		account:  "123456789012",
		action:   "s3:PutObject",
		res:      "arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar-logs/report.txt",
		want:     policy.ExplicitDeny,
		reason:   policy.IdentityDeny,
	},
	{
		name:     "own bucket allowed by both",
		src:      docEvalBasics,
		stated:   "Both the identity-based policy and the resource-based policy allow the request",
		resource: "carlos-bucket.json",
		identity: []string{"carlos-identity.json"},
		caller:   rpExampleUser,
		account:  "123456789012",
		action:   "s3:PutObject",
		res:      "arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar/report.txt",
		want:     policy.Allow,
	},
	{
		name:     "own bucket allowed by the bucket policy alone",
		src:      docEvalBasics,
		stated:   "If one of the policy types allows the request and the other doesn't, the request is still allowed",
		resource: "carlos-bucket.json",
		caller:   rpExampleUser,
		account:  "123456789012",
		action:   "s3:PutObject",
		res:      "arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar/report.txt",
		want:     policy.Allow,
	},
	{
		name:     "identity allow alone",
		src:      docEvalLogic,
		stated:   "If an action is allowed by an identity-based policy, a resource-based policy, or both, then AWS allows the action",
		resource: rpBucket("Allow", `"Principal":{"AWS":"`+rpOps.ARN+`"}`, ""),
		identity: []string{rpAllowGet},
		caller:   rpDev,
		want:     policy.Allow,
	},
	{
		name: "identity allow, no resource policy", src: docEvalLogic,
		stated:   "allowed by an identity-based policy",
		identity: []string{rpAllowGet}, caller: rpDev, want: policy.Allow,
	},
	{
		name:     "resource deny beats identity allow",
		src:      docEvalBasics,
		stated:   "If either of them explicitly denied the statement, the request would have been denied",
		resource: rpBucket("Deny", `"Principal":"*"`, ""),
		identity: []string{rpAllowGet},
		caller:   rpDev,
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
	},
	{
		name: "identity deny beats resource allow", src: docEvalLogic,
		stated:   "An explicit deny in either of these policies overrides the allow",
		resource: rpBucket("Allow", `"Principal":{"AWS":"`+rpDev.ARN+`"}`, ""),
		identity: []string{rpDenyGet}, caller: rpDev,
		want: policy.ExplicitDeny, reason: policy.IdentityDeny,
	},
	{
		name:     "both deny names the identity-based policy",
		src:      docAccessDenied,
		stated:   "CHOICE: AWS includes only one of those policy types in the error message; which is not documented",
		resource: rpBucket("Deny", `"Principal":"*"`, ""),
		identity: []string{rpDenyGet},
		caller:   rpDev,
		want:     policy.ExplicitDeny,
		reason:   policy.IdentityDeny,
	},
	{
		name:     "neither allows",
		src:      docEvalDenyAll,
		stated:   "CHOICE of reason: no statement in identity-based policies allows, so the request is implicitly denied",
		resource: rpBucket("Allow", `"Principal":{"AWS":"`+rpOps.ARN+`"}`, ""),
		caller:   rpDev,
		want:     policy.ImplicitDeny,
		reason:   policy.NoIdentityAllow,
	},
	// Source: docEvalDenyAll, Resource-based policies.
	{
		name:     "user arn grant needs no identity allow",
		src:      docEvalDenyAll,
		stated:   "resource-based policies that grant permissions to an IAM user ARN ... are not limited by an implicit deny in an identity-based policy",
		resource: rpBucket("Allow", `"Principal":{"AWS":"`+rpDev.ARN+`"}`, ""),
		caller:   rpDev,
		want:     policy.Allow,
	},
	{
		name: "role arn grant allows its session",
		src:  docEvalDenyAll,
		stated: "Resource-based policies that grant permissions to an IAM role ARN are limited by an implicit deny " +
			"in a permissions boundary or session policy ... the principal that makes the request is the IAM role session " +
			"(neither is evaluated here, so the grant stands alone)",
		resource: rpBucket(
			"Allow",
			`"Principal":{"AWS":"arn:aws:iam::`+rpAcct+`:role/Reader"}`,
			"",
		),
		caller: rpReader,
		want:   policy.Allow,
	},
	{
		name:     "session arn grant needs no identity allow",
		src:      docEvalDenyAll,
		stated:   "resource-based policies that grant permissions to an IAM role session ARN grant permissions directly to the assumed role session",
		resource: rpBucket("Allow", `"Principal":{"AWS":"`+rpReader.ARN+`"}`, ""),
		caller:   rpReader,
		want:     policy.Allow,
	},
	{
		name:     "session arn grant is that session only",
		src:      docEvalDenyAll,
		stated:   "the principal making the request is the IAM role session ARN",
		resource: rpBucket("Allow", `"Principal":{"AWS":"`+rpReader.ARN+`"}`, ""),
		caller: rpSession(
			rpAcct,
			"",
			"Reader",
			"s2",
		),
		want:   policy.ImplicitDeny,
		reason: policy.NoIdentityAllow,
	},
	{
		name:   "role arn grant does not allow an IAM user",
		src:    docPrincipal,
		stated: "a role principal names the role's sessions",
		resource: rpBucket(
			"Allow",
			`"Principal":{"AWS":"arn:aws:iam::`+rpAcct+`:role/Reader"}`,
			"",
		),
		caller: rpDev,
		want:   policy.ImplicitDeny,
		reason: policy.NoIdentityAllow,
	},
	{
		name:   "role arn with path",
		src:    docIdentifiers,
		stated: "ASSUMPTION: a role ARN is arn:aws:iam::account:role/role-name-with-path, so the path is part of it",
		resource: rpBucket(
			"Allow",
			`"Principal":{"AWS":"arn:aws:iam::`+rpAcct+`:role/ops/Reader"}`,
			"",
		),
		caller: rpSession(rpAcct, "ops/", "Reader", "s1"),
		want:   policy.Allow,
	},
	{
		name:   "role arn without the role's path",
		src:    docIdentifiers,
		stated: "ASSUMPTION: arn:...:role/Reader is not the ARN of role ops/Reader",
		resource: rpBucket(
			"Allow",
			`"Principal":{"AWS":"arn:aws:iam::`+rpAcct+`:role/Reader"}`,
			"",
		),
		caller: rpSession(
			rpAcct,
			"ops/",
			"Reader",
			"s1",
		),
		want:   policy.ImplicitDeny,
		reason: policy.NoIdentityAllow,
	},
	// Source: docPrincipal, AWS account principals.
	{
		name:     "account grant delegates to identity policies",
		src:      docPrincipal,
		stated:   "This delegates authority to the account ... an administrator in that account must then grant access to an identity",
		resource: rpBucket("Allow", `"Principal":{"AWS":"`+rpAcct+`"}`, ""),
		caller:   rpDev,
		want:     policy.ImplicitDeny,
		reason:   policy.NoIdentityAllow,
	},
	{
		name: "account grant with identity allow", src: docPrincipal,
		stated:   "an administrator ... must then grant access to an identity",
		resource: rpBucket("Allow", `"Principal":{"AWS":"`+rpAcct+`"}`, ""),
		identity: []string{rpAllowGet}, caller: rpDev, want: policy.Allow,
	},
	{
		name:   "root arn grant is the account",
		src:    docPrincipal,
		stated: "The account ARN and the shortened account ID behave the same way ... does not limit permissions to only the root user",
		resource: rpBucket(
			"Allow",
			`"Principal":{"AWS":"arn:aws:iam::`+rpAcct+`:root"}`,
			"",
		),
		caller: rpReader,
		want:   policy.ImplicitDeny,
		reason: policy.NoIdentityAllow,
	},
	{
		name:   "root arn grant with identity allow",
		src:    docPrincipal,
		stated: "Both delegate permissions to the account",
		resource: rpBucket(
			"Allow",
			`"Principal":{"AWS":"arn:aws:iam::`+rpAcct+`:root"}`,
			"",
		),
		identity: []string{rpAllowGet},
		caller:   rpReader,
		want:     policy.Allow,
	},
	// Source: docPrincipal, All principals.
	{
		name:     "star grant within the account",
		src:      docPrincipal,
		stated:   "For IAM users and role principals within your account, no other permissions are required",
		resource: rpBucket("Allow", `"Principal":"*"`, ""),
		caller:   rpReader,
		want:     policy.Allow,
	},
	{
		name: "aws star grant within the account", src: docPrincipal,
		stated:   `"Principal": "*" and "Principal" : { "AWS" : "*" } are equivalent`,
		resource: rpBucket("Allow", `"Principal":{"AWS":"*"}`, ""),
		caller:   rpDev, want: policy.Allow,
	},
	{
		name:   "user name is case sensitive",
		src:    docPrincipal,
		stated: "In a Principal element, the user name part of the ARN is case sensitive",
		resource: rpBucket(
			"Allow",
			`"Principal":{"AWS":"arn:aws:iam::`+rpAcct+`:user/Dev"}`,
			"",
		),
		caller: rpDev,
		want:   policy.ImplicitDeny,
		reason: policy.NoIdentityAllow,
	},
	{
		name:   "principal array is OR",
		src:    docPrincipal,
		stated: "This is a logical OR and not a logical AND",
		resource: rpBucket(
			"Allow",
			`"Principal":{"AWS":["`+rpOps.ARN+`","`+rpDev.ARN+`"]}`,
			"",
		),
		caller: rpDev,
		want:   policy.Allow,
	},
	// Source: docIdentifiers, Unique identifiers.
	{
		name: "user unique id", src: docIdentifiers,
		stated:   "You can create resource-based policies that grant access by unique ID",
		resource: rpBucket("Allow", `"Principal":{"AWS":"`+rpDev.UserID+`"}`, ""),
		caller:   rpDev, want: policy.Allow,
	},
	{
		name:   "role unique id",
		src:    docIdentifiers,
		stated: `unique IDs in the Principal element, such as "AROADBQP57FF2AEXAMPLE"; aws:userid is AROA...:role-session-name`,
		resource: rpBucket(
			"Allow",
			`"Principal":{"AWS":"AROAREADEREXAMPLE000000"}`,
			"",
		),
		caller: rpReader,
		want:   policy.Allow,
	},
	{
		name:   "service principal is not a Tule caller",
		src:    docPrincipal,
		stated: "ASSUMPTION: A service principal is an identifier for a service; no Caller is a service",
		resource: rpBucket(
			"Allow",
			`"Principal":{"Service":"s3.amazonaws.com"}`,
			"",
		),
		caller: rpDev,
		want:   policy.ImplicitDeny,
		reason: policy.NoIdentityAllow,
	},
	// Source: docPrincipal, the UsePrincipalArnInsteadOfNotPrincipalWithDeny
	// example, a bucket in 444455556666.
	{
		name:     "deny all but the named user: named user",
		src:      docPrincipal,
		stated:   "explicitly deny all principals except for the ones specified in the Condition element",
		resource: "principal-arn-instead-of-notprincipal.json",
		identity: []string{rpAllowGet},
		caller:   rpUser(rpOther, "user-name"),
		account:  rpOther,
		want:     policy.Allow,
	},
	{
		name:     "deny all but the named user: other user",
		src:      docPrincipal,
		stated:   "explicitly deny all principals except for the ones specified in the Condition element",
		resource: "principal-arn-instead-of-notprincipal.json",
		identity: []string{rpAllowGet},
		caller:   rpPartner,
		account:  rpOther,
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
	},
	// Source: docNotPrincipal, the DenyCrossAuditAccess example.
	{
		name:     "deny all roles but read-only-role: its session",
		src:      docNotPrincipal,
		stated:   "uses aws:PrincipalArn to explicitly allow the role read-only-role to access Amazon S3 buckets",
		resource: "deny-cross-audit-access.json",
		identity: []string{rpAllowGet},
		caller:   rpSession(rpOther, "", "read-only-role", "audit"),
		account:  rpOther,
		res:      "arn:aws:s3:::Bucket_Account_Audit/report",
		want:     policy.Allow,
	},
	{
		name:     "deny all roles but read-only-role: another role",
		src:      docNotPrincipal,
		stated:   "prevent all IAM roles, except those specified in the Condition element, from accessing",
		resource: "deny-cross-audit-access.json",
		identity: []string{rpAllowGet},
		caller:   rpSession(rpOther, "", "writer", "audit"),
		account:  rpOther,
		res:      "arn:aws:s3:::Bucket_Account_Audit/report",
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
	},
}

func TestConformanceResourceSameAccount(t *testing.T) { rpRun(t, rpSameAccountCases) }

// ---------------------------------------------------------------------------
// Across accounts

var (
	rpDemo = rpSession("111111111111", "", "Demo", "dev")
	// rpCross is a bucket in rpAcct; callers come from rpOther.
	rpCrossPartner = rpBucket("Allow", `"Principal":{"AWS":"`+rpPartner.ARN+`"}`, "")
	rpCrossOther   = rpBucket("Allow", `"Principal":{"AWS":"`+rpOther+`"}`, "")
	rpCrossStar    = rpBucket("Allow", `"Principal":"*"`, "")
	rpCrossDenied  = rpBucket("Deny", `"Principal":{"AWS":"`+rpOther+`"}`, "")
)

var rpCrossAccountCases = []rpCase{
	// Source: docCrossAccount, "Example cross-account policy evaluation".
	{
		name:   "demo logs bucket",
		src:    docCrossAccount,
		stated: "Because the request is explicitly denied within one of the accounts, the final decision is to deny the request",
		identity: []string{
			"cross-account-demo-identity.json",
		},
		caller:  rpDemo,
		account: "222222222222",
		action:  "s3:PutObject",
		res:     "arn:aws:s3:::amzn-s3-demo-bucket-production-logs/f",
		want:    policy.ExplicitDeny,
		reason:  policy.IdentityDeny,
	},
	{
		name:     "demo production bucket",
		src:      docCrossAccount,
		stated:   "Because both accounts allow the request, the final decision is to allow the request",
		resource: "cross-account-demo-bucket.json",
		identity: []string{"cross-account-demo-identity.json"},
		caller:   rpDemo,
		account:  "222222222222",
		action:   "s3:PutObject",
		res:      "arn:aws:s3:::amzn-s3-demo-bucket-production/f",
		want:     policy.Allow,
	},
	{
		name:     "demo cannot delete",
		src:      docCrossAccount,
		stated:   "The role can create and edit, but not delete the objects in the bucket",
		resource: "cross-account-demo-bucket.json",
		identity: []string{"cross-account-demo-identity.json"},
		caller:   rpDemo,
		account:  "222222222222",
		action:   "s3:DeleteObject",
		res:      "arn:aws:s3:::amzn-s3-demo-bucket-production/f",
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name: "identity allow without resource policy", src: docCrossAccount,
		stated:   "the resource-based policy in AccountB must allow the requester in AccountA",
		identity: []string{rpAllowGet}, caller: rpPartner,
		want: policy.ImplicitDeny, reason: policy.NoResourceAllow,
	},
	{
		name: "resource allow without identity allow", src: docCrossAccount,
		stated:   "the requester in the trusted AccountA must have an identity-based policy",
		resource: rpCrossPartner, caller: rpPartner,
		want: policy.ImplicitDeny, reason: policy.NoIdentityAllow,
	},
	{
		name:     "user grant and identity allow",
		src:      docCrossAccount,
		stated:   "AWS allows the request only if both account policy evaluations allow the request",
		resource: rpCrossPartner,
		identity: []string{rpAllowGet},
		caller:   rpPartner,
		want:     policy.Allow,
	},
	{
		name:     "account grant and identity allow",
		src:      docCrossAccount,
		stated:   "You can specify the entire account or its IAM users ... IAM roles, or assumed-role sessions",
		resource: rpCrossOther,
		identity: []string{rpAllowGet},
		caller:   rpSession(rpOther, "", "R", "s"),
		want:     policy.Allow,
	},
	{
		name:     "star grant needs identity allow",
		src:      docPrincipal,
		stated:   "For principals in other accounts, they must also have identity-based permissions in their account",
		resource: rpCrossStar,
		caller:   rpPartner,
		want:     policy.ImplicitDeny,
		reason:   policy.NoIdentityAllow,
	},
	{
		name:     "star grant and identity allow",
		src:      docPrincipal,
		stated:   "they must also have identity-based permissions in their account that allow them to access your resource",
		resource: rpCrossStar,
		identity: []string{rpAllowGet},
		caller:   rpPartner,
		want:     policy.Allow,
	},
	{
		name:     "grant to another account",
		src:      docPrincipal,
		stated:   "an account principal names that account",
		resource: rpBucket("Allow", `"Principal":{"AWS":"999988887777"}`, ""),
		identity: []string{
			rpAllowGet,
		},
		caller: rpPartner,
		want:   policy.ImplicitDeny,
		reason: policy.NoResourceAllow,
	},
	{
		name:     "resource deny across accounts",
		src:      docEvalDenyAll,
		stated:   "If the enforcement code finds even one explicit deny that applies, the enforcement code returns a final decision of Deny",
		resource: rpCrossDenied,
		identity: []string{rpAllowGet},
		caller:   rpPartner,
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
	},
	{
		name: "identity checked before resource", src: docAccessDenied,
		stated: "CHOICE: with neither allow, the identity-based policy type is named",
		caller: rpPartner, want: policy.ImplicitDeny, reason: policy.NoIdentityAllow,
	},
	{
		name:     "root of another account",
		src:      docEvalDenyAll,
		stated:   "all requests are implicitly denied with the exception of the AWS account root user, which has full access",
		resource: rpCrossOther,
		caller:   rpRoot(rpOther),
		want:     policy.Allow,
	},
	{
		name: "root of another account without a grant", src: docCrossAccount,
		stated: "the resource-based policy in AccountB must allow the requester in AccountA",
		caller: rpRoot(rpOther), want: policy.ImplicitDeny, reason: policy.NoResourceAllow,
	},
	{
		name:   "role arn grant across accounts",
		src:    docCrossAccount,
		stated: `the bucket policy names "arn:aws:iam::111111111111:role/Demo" and both accounts allow`,
		resource: rpBucket(
			"Allow",
			`"Principal":{"AWS":"arn:aws:iam::`+rpOther+`:role/R"}`,
			"",
		),
		identity: []string{
			rpAllowGet,
		},
		caller: rpSession(rpOther, "", "R", "s"),
		want:   policy.Allow,
	},
	{
		name:     "unknown resource account is cross-account",
		src:      docCrossAccount,
		stated:   "CHOICE: a resource account that is not an account ID is never the caller's, so both allows are needed",
		resource: rpBucket("Allow", `"Principal":{"AWS":"`+rpDev.ARN+`"}`, ""),
		caller:   rpDev,
		account:  "-",
		want:     policy.ImplicitDeny,
		reason:   policy.NoIdentityAllow,
	},
}

func TestConformanceResourceCrossAccount(t *testing.T) { rpRun(t, rpCrossAccountCases) }

// ---------------------------------------------------------------------------
// NotPrincipal

func rpNot(principals ...string) string {
	return rpBucket(
		"Deny",
		`"NotPrincipal":{"AWS":["`+strings.Join(principals, `","`)+`"]}`,
		"",
	)
}

var rpNotPrincipalCases = []rpCase{
	// Source: docNotPrincipal: "we strongly recommend that you explicitly
	// include the ARN for a user's account, or include both the ARN for a
	// role and the ARN for the account containing that role."
	{
		name:   "user and account exempt that IAM user",
		src:    docNotPrincipal,
		stated: "deny access to all principals except the principal specified in the NotPrincipal element",
		resource: rpNot(
			rpDev.ARN,
			rpAcct,
		),
		identity: []string{rpAllowGet},
		caller:   rpDev,
		want:     policy.Allow,
	},
	{
		name: "user and account deny another user", src: docNotPrincipal,
		stated:   "deny access to all principals except the principal specified",
		resource: rpNot(rpDev.ARN, rpAcct), identity: []string{rpAllowGet}, caller: rpOps,
		want: policy.ExplicitDeny, reason: policy.ResourceDeny,
	},
	{
		name:     "role and account exempt its session",
		src:      docNotPrincipal,
		stated:   "include both the ARN for a role and the ARN for the account containing that role",
		resource: rpNot("arn:aws:iam::"+rpAcct+":role/Reader", "arn:aws:iam::"+rpAcct+":root"),
		identity: []string{rpAllowGet},
		caller:   rpReader,
		want:     policy.Allow,
	},
	{
		name: "user without its account",
		src:  docNotPrincipal,
		stated: "CHOICE: Otherwise, the policy might deny access to the entire account containing the principal; " +
			"the strict reading is taken",
		resource: rpNot(rpDev.ARN),
		identity: []string{rpAllowGet},
		caller:   rpDev,
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
	},
	{
		name:   "role without its account",
		src:    docNotPrincipal,
		stated: "CHOICE: AWS might validate the account first, then the role; the strict reading is taken",
		resource: rpNot(
			"arn:aws:iam::" + rpAcct + ":role/Reader",
		),
		identity: []string{rpAllowGet},
		caller:   rpReader,
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
	},
	{
		name: "cross-account user exempt", src: docNotPrincipal,
		stated:   "include the ARN for a user's account",
		resource: rpNot(rpPartner.ARN, rpOther), identity: []string{rpAllowGet}, caller: rpPartner,
		want: policy.ImplicitDeny, reason: policy.NoResourceAllow,
	},
}

func TestConformanceResourceNotPrincipal(t *testing.T) { rpRun(t, rpNotPrincipalCases) }

// ---------------------------------------------------------------------------
// A session whose role was deleted

// srcOrphan: for a role session with an empty PrincipalARN nothing that
// names the role matches, and aws:PrincipalArn is absent, never derived.
// AWS's own behavior follows from its binding of a role ARN to the role's
// unique ID: "if you delete the role, then you break the relationship. The
// policy no longer applies" (docPrincipal). CHOICE, per review: Authorize
// goes further and denies such a session outright, before any policy is
// read, since without aws:PrincipalArn a Deny keyed on the role's ARN
// would not apply to it; identity refuses it everything but
// GetCallerIdentity.
var rpOrphanReader = rpOrphan(rpReader)

const rpOrphanStated = "CHOICE: a session whose role was deleted is denied before any policy is read"

// rpOrphanRow is a row for rpOrphanReader that must be denied outright.
func rpOrphanRow(name, resource string, identity []string, account string, c cfCtx) rpCase {
	return rpCase{
		name:     name,
		src:      srcOrphan,
		stated:   rpOrphanStated,
		resource: resource,
		identity: identity,
		caller:   rpOrphanReader,
		account:  account,
		ctx:      c,
		want:     policy.ImplicitDeny,
		reason:   policy.NoIdentityAllow,
	}
}

var rpOrphanCases = []rpCase{
	{
		name: "control: role arn grant allows the live session", src: docEvalDenyAll,
		stated:   "a resource-based grant to the role ARN reaches its session",
		resource: rpBucket("Allow", `"Principal":{"AWS":"`+rpReader.PrincipalARN+`"}`, ""),
		caller:   rpReader, want: policy.Allow,
	},
	rpOrphanRow("role arn grant",
		rpBucket("Allow", `"Principal":{"AWS":"`+rpReader.PrincipalARN+`"}`, ""), nil, "", nil),
	rpOrphanRow(
		"session arn grant",
		rpBucket("Allow", `"Principal":{"AWS":"`+rpReader.ARN+`"}`, ""),
		nil,
		"",
		nil,
	),
	rpOrphanRow("role unique id grant",
		rpBucket("Allow", `"Principal":{"AWS":"AROAREADEREXAMPLE000000"}`, ""), nil, "", nil),
	rpOrphanRow(
		"role arn grant across accounts",
		rpBucket(
			"Allow",
			`"Principal":{"AWS":"`+rpReader.PrincipalARN+`"}`,
			"",
		),
		[]string{rpAllowGet},
		rpOther,
		nil,
	),
	rpOrphanRow(
		"aws:PrincipalArn condition grant with the key forged in Context",
		rpBucket(
			"Allow",
			`"Principal":"*"`,
			`{"ArnEquals":{"aws:PrincipalArn":"`+rpReader.PrincipalARN+`"}}`,
		),
		nil,
		"",
		cfCtx{"aws:PrincipalArn": {rpReader.PrincipalARN}},
	),
	rpOrphanRow("account grant with identity allow",
		rpBucket("Allow", `"Principal":{"AWS":"`+rpAcct+`"}`, ""), []string{rpAllowGet}, "", nil),
	rpOrphanRow("star grant", rpBucket("Allow", `"Principal":"*"`, ""), nil, "", nil),
	rpOrphanRow("identity allow alone", "", []string{rpAllowGet}, "", nil),
	// The review's case: a Deny keyed on aws:userid must not be escaped.
	rpOrphanRow(
		"identity allow and a Deny keyed on aws:userid",
		rpBucket(
			"Deny",
			`"Principal":"*"`,
			`{"StringLike":{"aws:userid":"AROAREADEREXAMPLE000000:*"}}`,
		),
		[]string{rpAllowGet},
		"",
		nil,
	),
}

func TestConformanceResourceOrphanedSession(t *testing.T) { rpRun(t, rpOrphanCases) }

// Source: docAccessDenied: "AWS includes the phrase with an explicit deny
// in a {{type}} policy" and "because no {{type}} policy allows the
// {{action}} action"; its examples spell the types identity-based and
// resource-based.
func TestConformanceResourceReasonMessages(t *testing.T) {
	for r, want := range map[policy.Reason]string{
		policy.IdentityDeny:    "with an explicit deny in an identity-based policy",
		policy.ResourceDeny:    "with an explicit deny in a resource-based policy",
		policy.NoIdentityAllow: "because no identity-based policy allows the secretsmanager:GetSecretValue action",
		policy.NoResourceAllow: "because no resource-based policy allows the secretsmanager:GetSecretValue action",
		policy.NoReason:        "",
	} {
		if got := r.Message("secretsmanager:GetSecretValue"); got != want {
			t.Errorf("%v.Message = %q, want %q (source: %s)", r, got, want, docAccessDenied)
		}
	}
}

// ---------------------------------------------------------------------------
// Caller descriptors whose fields disagree

// rpForged is a root-typed descriptor carrying a user ARN of another
// account: its fields disagree, so Authorize must not take it for root.
var rpForged = policy.Caller{
	AccountID: rpOther, ARN: rpPartner.ARN, PrincipalARN: rpPartner.ARN, UserID: rpOther,
	Type: policy.PrincipalTypeAccount,
}

const rpMismatchStated = "CHOICE: a Caller whose fields disagree is refused before any policy is read"

var rpMismatchCases = []rpCase{
	{
		name: "account type with a user arn", src: srcCaller, stated: rpMismatchStated,
		resource: rpBucket("Allow", `"Principal":{"AWS":"`+rpOther+`"}`, ""), caller: rpForged,
		want: policy.ImplicitDeny, reason: policy.NoIdentityAllow,
	},
	{
		name:   "control: the real root of that account",
		src:    docEvalDenyAll,
		stated: "the AWS account root user ... has full access",
		resource: rpBucket(
			"Allow",
			`"Principal":{"AWS":"`+rpOther+`"}`,
			"",
		),
		caller: rpRoot(rpOther),
		want:   policy.Allow,
	},
	{
		name: "arn of another account than AccountID", src: srcCaller, stated: rpMismatchStated,
		resource: rpBucket("Allow", `"Principal":{"AWS":"`+rpPartner.ARN+`"}`, ""),
		identity: []string{rpAllowGet},
		caller: func() policy.Caller {
			c := rpPartner
			c.AccountID = rpAcct
			return c
		}(),
		want: policy.ImplicitDeny, reason: policy.NoIdentityAllow,
	},
	{
		name: "session claiming another role", src: srcCaller, stated: rpMismatchStated,
		resource: rpBucket("Allow", `"Principal":{"AWS":"arn:aws:iam::`+rpAcct+`:role/Admin"}`, ""),
		caller: func() policy.Caller {
			c := rpReader
			c.PrincipalARN = "arn:aws:iam::" + rpAcct + ":role/Admin"
			return c
		}(),
		want: policy.ImplicitDeny, reason: policy.NoIdentityAllow,
	},
	{
		name: "user without a unique id", src: srcCaller, stated: rpMismatchStated,
		resource: rpBucket("Allow", `"Principal":"*"`, ""),
		caller: func() policy.Caller {
			c := rpDev
			c.UserID = ""
			return c
		}(),
		want: policy.ImplicitDeny, reason: policy.NoIdentityAllow,
	},
	{
		name: "unknown type", src: srcCaller, stated: rpMismatchStated,
		resource: rpBucket("Allow", `"Principal":"*"`, ""),
		caller: func() policy.Caller {
			c := rpDev
			c.Type = "FederatedUser"
			return c
		}(),
		want: policy.ImplicitDeny, reason: policy.NoIdentityAllow,
	},
}

func TestConformanceResourceCallerMismatch(t *testing.T) { rpRun(t, rpMismatchCases) }

// ---------------------------------------------------------------------------
// Review rows: NotPrincipal sessions, aws:username, partitions

var rpReviewCases = []rpCase{
	{
		name: "NotPrincipal account and session arn deny the session",
		src:  docNotPrincipal,
		stated: "CHOICE: include both the ARN for a role and the ARN for the account containing that role; " +
			"the session ARN does not stand in for the role",
		resource: rpNot(rpReader.ARN, rpAcct),
		identity: []string{rpAllowGet},
		caller:   rpReader,
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
	},
	{
		name:   "NotPrincipal account and role id exempt the session",
		src:    docNotPrincipal,
		stated: "include both the ARN for a role and the ARN for the account containing that role (the role by its ID)",
		resource: rpNot(
			rpID("AROA", "Reader"),
			rpAcct,
		),
		identity: []string{rpAllowGet},
		caller:   rpReader,
		want:     policy.Allow,
	},
	{
		name: "aws:username forged in Context for a session",
		src:  docVariables,
		stated: "aws:username is present for IAM users only; CHOICE: the Caller supplies it and Context " +
			"cannot",
		identity: []string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject",` +
				`"Resource":"*","Condition":{"StringEquals":{"aws:username":"admin"}}}}`,
		},
		caller: rpReader,
		ctx:    cfCtx{"aws:username": {"admin"}},
		want:   policy.ImplicitDeny,
		reason: policy.NoIdentityAllow,
	},
	{
		name:   "aws:username of a user",
		src:    docVariables,
		stated: "aws:username is the user's friendly name",
		identity: []string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject",` +
				`"Resource":"*","Condition":{"StringEquals":{"aws:username":"dev"}}}}`,
		},
		caller: rpDev,
		ctx:    cfCtx{"aws:username": {"admin"}},
		want:   policy.Allow,
	},
	{
		name: "account id principal names the caller's account in any partition",
		src:  docPrincipal,
		stated: "CHOICE: an account ID carries no partition, so it is matched by the caller's AccountID " +
			"alone; matching never depends on the request's resource",
		resource: rpBucket(
			"Allow",
			`"Principal":{"AWS":"`+rpOther+`"}`,
			"",
		),
		identity: []string{rpAllowGet},
		caller:   rpCN,
		want:     policy.Allow,
	},
	{
		name:     "root arn principal in another partition",
		src:      docIdentifiers,
		stated:   "You cannot delegate access between accounts in different partitions",
		resource: rpBucket("Allow", `"Principal":{"AWS":"arn:aws:iam::`+rpOther+`:root"}`, ""),
		identity: []string{
			rpAllowGet,
		},
		caller: rpCN,
		want:   policy.ImplicitDeny,
		reason: policy.NoResourceAllow,
	},
}

// rpCN is a user of rpOther in the aws-cn partition.
var rpCN = policy.Caller{
	AccountID: rpOther, ARN: "arn:aws-cn:iam::" + rpOther + ":user/partner",
	PrincipalARN: "arn:aws-cn:iam::" + rpOther + ":user/partner", UserID: rpID("AIDA", "partner"),
	Type: policy.PrincipalTypeUser,
}

func TestConformanceResourceReview(t *testing.T) { rpRun(t, rpReviewCases) }

// rpListDeny is a resource-based policy with a Deny naming principal and
// an Allow for everyone, both on every resource, for a request on "*",
// as a List action without a resource type makes.
func rpListDeny(principal string) string {
	return `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"Deny","Effect":"Deny","Principal":{"AWS":"` + principal + `"},"Action":"*","Resource":"*"},` +
		`{"Sid":"Allow","Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`
}

const allowAllIdentity = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`

// Principal matching never depends on the request's resource being an
// ARN: an account Deny must apply on "*" as on any resource.
var rpStarResourceCases = []rpCase{
	{
		name:     "account id deny on resource star",
		src:      docEvalDenyAll,
		stated:   "If the enforcement code finds even one explicit deny that applies ... Deny",
		resource: rpListDeny(rpAcct),
		identity: []string{allowAllIdentity},
		caller:   rpDev,
		action:   "s3:ListAllMyBuckets",
		res:      "*",
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
	},
	{
		name:   "root arn deny on resource star",
		src:    docPrincipal,
		stated: "The account ARN and the shortened account ID behave the same way",
		resource: rpListDeny(
			"arn:aws:iam::" + rpAcct + ":root",
		),
		identity: []string{allowAllIdentity},
		caller:   rpReader,
		action:   "sqs:ListQueues",
		res:      "*",
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
	},
	{
		name: "control: another account's deny on resource star", src: docPrincipal,
		stated:   "an account principal names that account",
		resource: rpListDeny(rpOther), identity: []string{allowAllIdentity}, caller: rpDev,
		action: "secretsmanager:ListSecrets", res: "*", want: policy.Allow,
	},
}

func TestConformanceResourceStarResource(t *testing.T) { rpRun(t, rpStarResourceCases) }

// ---------------------------------------------------------------------------
// Principal values at parse

// rpPrincipalDoc is a policy whose one statement names principal (an AWS
// value) and, for a resource-based policy, a resource.
func rpPrincipalDoc(principal string, resource bool) string {
	r := ""
	action := "sts:AssumeRole"
	if resource {
		r, action = `,"Resource":"arn:aws:s3:::amzn-s3-demo-bucket/*"`, "s3:GetObject"
	}
	return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"` + principal +
		`"},"Action":"` + action + `"` + r + `}}`
}

//nolint:govet // fieldalignment: field order reads as the table rows do.
var rpPrincipalParseCases = []struct {
	name, src, stated, principal string
	ok                           bool
}{
	{
		"root arn",
		docPrincipal,
		"arn:aws:iam::account-ID:root",
		"arn:aws:iam::" + rpAcct + ":root",
		true,
	},
	{
		"root arn with a region", docIdentifiers, "For IAM resources, this is always kept blank",
		"arn:aws:iam:us-east-1:" + rpAcct + ":root", false,
	},
	{
		"root arn with a short account",
		docIdentifiers,
		"account specifies the AWS account ID with no hyphens",
		"arn:aws:iam::12345:root",
		false,
	},
	{
		"user arn with a path",
		docIdentifiers,
		"user/user-name-with-path",
		"arn:aws:iam::" + rpAcct + ":user/a/b/dev",
		true,
	},
	{
		"role arn with a path",
		docIdentifiers,
		"role/role-name-with-path",
		"arn:aws:iam::" + rpAcct + ":role/a/Reader",
		true,
	},
	{
		"session arn", docPrincipal, "assumed-role/role-name/role-session-name",
		"arn:aws:sts::" + rpAcct + ":assumed-role/Reader/s1", true,
	},
	{
		"federated user arn",
		docPrincipal,
		"You can specify federated user sessions in the Principal element of a resource-based policy",
		"arn:aws:sts::" + rpAcct + ":federated-user/dev",
		true,
	},
	{
		"group arn", docPrincipal, "You cannot identify a user group as a principal in a policy",
		"arn:aws:iam::" + rpAcct + ":group/Developers", false,
	},
	{
		"policy arn",
		docPrincipal,
		"not a principal type the page lists",
		"arn:aws:iam::" + rpAcct + ":policy/P",
		false,
	},
	{
		"upper-case ROOT",
		docIdentifiers,
		"arn:aws:iam::account:root",
		"arn:aws:iam::" + rpAcct + ":ROOT",
		false,
	},
	{
		"trailing space",
		docIdentifiers,
		"UserName pattern [\\w+=,.@-]+",
		"arn:aws:iam::" + rpAcct + ":user/dev ",
		false,
	},
	{
		"session arn without a session", docPrincipal, "assumed-role/role-name/role-session-name",
		"arn:aws:sts::" + rpAcct + ":assumed-role/Reader", false,
	},
	{
		"session arn with an empty session",
		docPrincipal,
		"assumed-role/role-name/role-session-name",
		"arn:aws:sts::" + rpAcct + ":assumed-role/Reader/",
		false,
	},
	{
		"user arn without a name",
		docIdentifiers,
		"user/user-name-with-path",
		"arn:aws:iam::" + rpAcct + ":user/",
		false,
	},
	{
		"user arn with a path and no name", docIdentifiers, "user/user-name-with-path",
		"arn:aws:iam::" + rpAcct + ":user/team/", false,
	},
	{
		"policy variable",
		docPrincipal,
		"You cannot use a wildcard to match part of a principal name or ARN; " +
			"Principal is not among the elements that take variables",
		"arn:aws:iam::" + rpAcct + ":user/${aws:username}",
		false,
	},
	{
		"empty partition", docIdentifiers, "partition identifies the partition for the resource",
		"arn::iam::" + rpAcct + ":user/dev", false,
	},
	{
		"other service",
		docPrincipal,
		"an AWS principal is an IAM or STS identity",
		"arn:aws:s3:::" + rpAcct,
		false,
	},
}

// Principal values in resource-based policies (ParseResource), and the
// regional root ARN in a trust policy (ParseTrust) too. Refusals carry
// IAM's "Invalid principal in policy".
func TestConformanceResourcePrincipalParse(t *testing.T) {
	for _, c := range rpPrincipalParseCases {
		t.Run(c.name, func(t *testing.T) {
			_, err := policy.ParseResource([]byte(rpPrincipalDoc(c.principal, true)))
			rpCheckParse(t, err, c.ok, c.src, c.stated)
		})
	}
	trust := map[string]bool{
		"arn:aws:iam::" + rpAcct + ":root":          true,
		"arn:aws:iam:us-east-1:" + rpAcct + ":root": false,
		"arn:aws:iam::12345:root":                   false,
	}
	for principal, ok := range trust {
		t.Run("trust "+principal, func(t *testing.T) {
			_, err := policy.ParseTrust([]byte(rpPrincipalDoc(principal, false)))
			rpCheckParse(t, err, ok, docIdentifiers, "For IAM resources, this is always kept blank")
			_, err = policy.Parse([]byte(rpPrincipalDoc(principal, false)))
			rpCheckParse(t, err, ok, docIdentifiers, "Parse takes the same principal values")
		})
	}
}

func rpCheckParse(t *testing.T, err error, ok bool, src, stated string) {
	t.Helper()
	if ok {
		if err != nil {
			t.Errorf("refused: %v (source: %s; %s)", err, src, stated)
		}
		return
	}
	var pe *policy.ParseError
	if !errors.As(err, &pe) || pe.Message != "Invalid principal in policy" {
		t.Errorf("got %v, want Invalid principal in policy (source: %s; %s)", err, src, stated)
	}
}
