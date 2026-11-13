# policy

A Go library that parses AWS IAM policy documents and evaluates requests
against them with the logic AWS applies, for the Tule services that stand in
for AWS ones: identity-based policies within one account (`Evaluate`), role
trust policies for AssumeRole (`TrustMatch`), and identity-based and
resource-based policies together, within one account and across accounts
(`Authorize`).

It depends on the standard library only, and has no Tule types. Every rule
below is taken from the IAM User Guide and cited, with the page, in a
comment where it is implemented.

## Installing

```sh
go get tule.dev/policy
```

Go 1.27.4 or later.

## Usage

```go
p, err := policy.ParseIdentity(doc) // ParseTrust for a role trust policy
if err != nil {
	var pe *policy.ParseError
	if errors.As(err, &pe) {
		// Return pe.Message as IAM's MalformedPolicyDocument (HTTP 400).
	}
	return err
}

res := policy.Evaluate(policy.Request{
	Action:    "s3:GetObject",
	Resource:  "arn:aws:s3:::bucket/key",
	Principal: "arn:aws:iam::123456789012:user/alice",
	Context:   map[string][]string{"aws:SourceIp": {"203.0.113.7"}},
}, p, other)
if res.Decision != policy.Allow {
	// AccessDenied. res.Policy and res.Sid name the deciding statement.
}

tr := policy.TrustMatch(trust, roleAccountID, "sts:AssumeRole", callerARN, ctx)
// tr.Decision, and tr.Direct for whether an identity Allow is also needed.

bucketPolicy, err := policy.ParseResource(doc) // refuse a bad one when it is stored
az := policy.Authorize(policy.AuthorizeRequest{
	Action:          "s3:GetObject",
	Resource:        "arn:aws:s3:::bucket/key",
	ResourceAccount: bucketAccountID,
	Caller: policy.Caller{ // from sigv4's Principal
		AccountID:    p.AccountID,
		ARN:          p.ARN,
		PrincipalARN: p.PrincipalARN,
		UserID:       p.UserID,
		Type:         policy.PrincipalType(p.Type),
	},
	Context: ctx,
}, bucketPolicy, identityPolicies...) // bucketPolicy may be nil
if az.Decision != policy.Allow {
	// AccessDenied: "User: <arn> is not authorized to perform: <action> on
	// resource: <arn> " + az.Reason.Message(action)
}
```

## API

- `ParseIdentity(doc []byte) (*Policy, error)` parses an identity-based
  policy: no statement may have `Principal` or `NotPrincipal`, and each needs
  `Resource` or `NotResource`.
- `ParseTrust(doc []byte) (*Policy, error)` parses a role trust policy: each
  statement needs `Principal`, and may have no `Resource`, `NotResource` or
  `NotPrincipal`.
- `Parse(doc []byte) (*Policy, error)` is the lenient, kind-agnostic form:
  it checks the grammar of both kinds without either kind's element rules
  (a statement needs a `Resource` only when it has no `Principal`). It is
  for tools that inspect documents, not for authorization: use
  `ParseIdentity` for policies passed to `Evaluate` and `ParseTrust` for
  policies passed to `TrustMatch`. Even so, `Evaluate` never applies a
  statement that has a `Principal` or `NotPrincipal`, and `TrustMatch`
  never applies one that lacks a `Principal` or has a `Resource`.
- A `*Policy` is immutable and safe for concurrent use. Size limits are the
  caller's to apply.
- `Request{Action, Resource, Principal string; Context map[string][]string}`.
  `Principal` is the caller's ARN. Context keys are matched
  case-insensitively.
- `Decision`: `ImplicitDeny` (the zero value), `Allow`, `ExplicitDeny`, with
  `String()`.
- `Result{Decision Decision; Policy int; Sid string}`. `Policy` is the index
  of the deciding policy among those passed to `Evaluate`, or -1 for an
  implicit deny; `Sid` is the deciding statement's Sid.
- `Evaluate(req Request, policies ...*Policy) Result`. Nil policies are
  skipped.
- `TrustMatch(trust *Policy, roleAccount, action, principalARN string, ctx
  map[string][]string) TrustResult`, with `TrustResult{Decision Decision;
  Direct bool; Sid string}`. `roleAccount` is the account ID of the role the
  trust policy is attached to. `Direct` is true when the caller is in that
  account and an allowing statement named it other than through its
  account.
- `AllowsPrincipal(trust *Policy, action, principalARN string, ctx
  map[string][]string) bool` is `TrustMatch(...).Decision == Allow`.
- `ParseResource(doc []byte) (*Policy, error)` parses a resource-based
  policy (bucket, queue, secret, function, email identity policy): each
  statement needs `Principal` or `NotPrincipal` (reported first when
  missing, `Missing required field Principal.`) and `Resource` or
  `NotResource`. An `AWS` principal is `"*"`, a 12-digit account ID, a
  user (`AIDA...`) or role (`AROA...`) unique ID, or one of these ARNs,
  each with a partition, a blank region and a 12-digit account:
  `arn:P:iam::A:root`, `arn:P:iam::A:user/PATH/NAME`,
  `arn:P:iam::A:role/PATH/NAME`, `arn:P:sts::A:assumed-role/ROLE/SESSION`,
  `arn:P:sts::A:federated-user/NAME` ("You can specify federated user
  sessions in the Principal element of a resource-based policy"). Names
  follow the IAM and STS APIs' pattern `[\w+=,.@-]+`, and a path is
  printable ASCII. Anything else is refused with `Invalid principal in
  policy`: a group ("You cannot identify a user group as a principal"), a
  policy or other IAM ARN, `:ROOT`, a trailing space, a session ARN
  without a session, a user or role ARN without a name, a policy variable.
  `Federated` is refused. Services may layer their own checks, such as
  S3's requirement that `Resource` name the bucket.
- `Caller{AccountID, ARN, PrincipalARN, UserID string; Type PrincipalType}`
  describes the principal making a request, with the meanings of
  tule.dev/sigv4 v0.4.1's `Principal` fields of the same names.
  `PrincipalType` is `PrincipalTypeAccount` (`"Account"`, the root user),
  `PrincipalTypeUser` (`"User"`) or `PrincipalTypeAssumedRole`
  (`"AssumedRole"`). A role session with an empty `PrincipalARN` is a
  session whose role was deleted.
- `AuthorizeRequest{Action, Resource, ResourceAccount string; Caller Caller;
  Context map[string][]string}`. `ResourceAccount` is the account ID that
  owns the resource.
- `Authorize(req AuthorizeRequest, resource *Policy, identity ...*Policy)
  Authorization`. `resource` is the resource's resource-based policy, nil
  when it has none; nil identity policies are skipped.
- `Authorization{Decision Decision; Reason Reason; Identity, Resource
  Result; Direct bool}`. `Identity` is the identity policies' result as
  `Evaluate` gives it; `Resource` is the resource policy's (`Policy` 0, or
  -1 when no statement decided); `Direct` is whether a resource-based Allow
  named the caller other than through its account.
- `Reason`: `NoReason` (the zero value, for an Allow), `IdentityDeny`,
  `ResourceDeny`, `NoIdentityAllow`, `NoResourceAllow`, with `String()` and
  `Message(action string) string`, the phrase AWS ends its AccessDenied
  message with: `with an explicit deny in an identity-based policy`, `with
  an explicit deny in a resource-based policy`, `because no identity-based
  policy allows the <action> action`, `because no resource-based policy
  allows the <action> action` (`troubleshoot_access-denied.html`).
- `ParseError{Message string}`, returned by the parsers as `*ParseError`.

## Semantics and sources

Pages are in the IAM User Guide, `https://docs.aws.amazon.com/IAM/latest/UserGuide/`.

**Evaluation** (`reference_policies_evaluation-logic_policy-eval-denyallow.html`,
`reference_policies_evaluation-logic_policy-eval-basics.html`). An explicit
deny in any policy wins; otherwise any Allow allows; otherwise the request is
implicitly denied. The deciding statement is the first Deny that applies, in
policy then statement order, or else the first Allow. A statement applies
when its action, resource and every condition match. A statement with a
`Principal` or `NotPrincipal` never applies in `Evaluate`, since an
identity-based policy has none (`reference_policies_elements_principal.html`). A statement with no
`Resource` or `NotResource` applies to no resource in `Evaluate`.

**Grammar** (`reference_policies_grammar.html`, `reference_policies_elements_*.html`).
`Version` is `2012-10-17` or `2008-10-17`; without it the policy is
`2008-10-17` (`troubleshoot_policies.html`). `Statement` is one object or a
non-empty array. Elements appear in any order, at most once each, with names
matched exactly; unknown elements and repeated JSON keys are rejected. `Effect`
is `Allow` or `Deny` exactly. Each statement has `Action` or `NotAction`, and
`Resource` or `NotResource` unless it has a `Principal` or `NotPrincipal`
(a trust policy names no resource). An action is `*` or `vendor:name`. A
resource is `*` or an ARN with a vendor without wildcards. A `Sid` is
alphanumeric and unique in the policy. `NotPrincipal` requires `Deny`.
Condition values are strings, numbers or booleans, or non-empty arrays of
them, valid for their operator (see Conditions).

**Actions** (`reference_policies_elements_action.html`, `..._notaction.html`).
Case-insensitive, with `*` and `?`.

**Resources** (`reference_policies_elements_resource.html`, `reference-arns.html`,
`..._notresource.html`). Case-sensitive. `*` and `?` work within a field of
the ARN; a `*` that ends one of the first five fields may match across
colons, and in the resource field (which may itself hold colons) `*`
matches anything. `"*"` matches every resource. An ARN with fewer than six
fields is completed with `*` fields, so `arn:aws:sqs` is
`arn:aws:sqs:*:*:*` (`reference_policies_grammar.html`).

**Policy variables** (`reference_policies_variables.html`). With Version
`2012-10-17` only, `${key}` is replaced by the request's value for the
single-valued key `key` (case-insensitive), `${key, 'default'}` falls back
to `default`, and `${*}`, `${?}`, `${$}` stand for those characters. A
variable's value is always literal, never a wildcard. Variables are
replaced in the resource field of `Resource`/`NotResource` entries (after
the fifth colon) and in the values of String, ARN and Bool conditions. An
entry whose variable has no value matches no resource; a condition value
whose variable has no value matches nothing, so a negated operator then
holds. `aws:username`, `aws:PrincipalAccount`, `aws:PrincipalArn` and, for
the root user, `aws:userid` are derived from `Request.Principal` when
`Context` lacks them; `Context` wins.

**Conditions** (`reference_policies_elements_condition.html`,
`reference_policies_elements_condition_operators.html`,
`reference_policies_condition-logic-multiple-context-keys-or-values.html`,
`reference_policies_condition-single-vs-multi-valued-context-keys.html`).

- Operators: `StringEquals`, `StringNotEquals`, `StringEqualsIgnoreCase`,
  `StringNotEqualsIgnoreCase`, `StringLike`, `StringNotLike`; `Numeric*` and
  `Date*` (`Equals`, `NotEquals`, `LessThan`, `LessThanEquals`,
  `GreaterThan`, `GreaterThanEquals`); `Bool`; `BinaryEquals`; `IpAddress`,
  `NotIpAddress`; `ArnEquals`, `ArnLike`, `ArnNotEquals`, `ArnNotLike`;
  `Null`. Each takes `...IfExists` (except `Null`) and `ForAllValues:` or
  `ForAnyValue:` (except `Null`).
- Operators are ANDed, keys under one operator are ANDed, and a key's values
  are ORed; a negated operator holds when no value matches (NOR).
- A missing key: false, but true for a negated operator; true with
  `IfExists`; true for `ForAllValues`, false for `ForAnyValue`. For the set
  operators an empty-string value is no value: `["", "x"]` is `["x"]`, and a
  key whose values are all `""` counts as missing. `Null` with `true` holds
  when the key is absent, with `false` when present.
- `ForAnyValue` holds when at least one request value passes, `ForAllValues`
  when all do; a value passes a negated operator when it matches no policy
  value.
- Numbers are decimal (sign, digits, fraction, exponent up to ±400) and
  compared exactly, as rationals, so `100.000000000000001` is greater than
  `100`. Dates are the W3C ISO 8601 profile or epoch seconds. IP values are
  CIDR, a bare address being /32 (or /128 for IPv6). Binary values are
  base64 on both sides, compared decoded. `ArnLike` checks the six fields
  separately, each with `*` and `?`.
- **Malformed conditions are refused at Parse.** An unknown operator
  (including any spelling other than the documented one, and any unknown
  prefix or suffix combination) is a parse error, as is a policy value that
  cannot be valid for its operator: not a number for Numeric, not a date for
  Date, not an address or CIDR for IpAddress, not base64 for BinaryEquals,
  not `true`/`false` for Bool or Null, and for the ARN operators not an ARN:
  six colon-separated fields, the first `arn`, with a non-empty partition
  and service. A Bool value holding a policy variable, and an ARN value
  whose fields come from a variable (such as `${aws:PrincipalArn}`), are
  checked only at evaluation. In an ARN value with six fields of its own, a
  colon in a variable's value is literal text within its field. A Deny
  statement in a parsed policy therefore fails to apply only because the
  request lacks a key or its values do not match, never because the policy
  is malformed.
- **Malformed request values never grant and always deny.** A request value
  that is invalid for its operator (`"abc"` for a Numeric operator, a value
  that is not an ARN by the rule above for an ARN operator, an epoch outside
  years 0000 to 9999 for a Date operator) is neither a match nor a
  non-match: it takes the result worse for the caller. In an Allow statement
  it never helps the condition hold; in a Deny statement it always counts
  toward the condition holding. This holds under every operator, plain,
  negated, `ForAnyValue` and `ForAllValues`, while the key's valid values
  are compared as usual, so appending a junk value can neither switch a Deny
  off nor switch an Allow on. A policy value that a variable turns invalid
  follows the same rule. AWS documents neither case; this is a deliberate
  choice.

**Trust policies** (`reference_policies_elements_principal.html`,
`..._notprincipal.html`). `TrustMatch` applies the same deny-wins logic to
statements whose action matches, whose `Principal` names the caller (or
whose `NotPrincipal` does not), and whose conditions hold; a statement with
no `Principal` or with a `Resource` never applies. Each principal type takes
only its own kind of value, and anything else is refused at parse: `AWS` an
account ID, an IAM or STS ARN with a blank region and a 12-digit account
("For IAM resources, this is always kept blank."; `reference_identifiers.html`),
or `"*"`; `Service` a service principal such
as `ecs.amazonaws.com`; `Federated` a SAML or OIDC provider ARN or a
built-in provider such as `accounts.google.com`; `CanonicalUser` a 64-digit
hexadecimal ID. Partial wildcards are refused. `"*"` and `{"AWS":"*"}` match
anyone. An account ID or `arn:...:iam::ACCOUNT:root` matches every
principal of the account. A role ARN matches the role's sessions
(`arn:...:sts::ACCOUNT:assumed-role/NAME/SESSION`, by partition, account and
name, so a role path does not matter). Other values match exactly. Only the
`principalARN` argument identifies the caller; the context, including
`aws:PrincipalArn`, plays no part in matching principals.

`TrustMatch` also reports whether the Allow is direct: the caller is a
principal of the role's own account (`roleAccount`) and an allowing
statement named it by its own user, role or role-session ARN, or by `"*"`,
rather than only by an account ID or root ARN. A match in another account
is never direct, nor is a caller without an account in its ARN, such as a
service principal. Its `Sid` is the first direct allowing statement's, else
the first allowing statement's. Within one account AWS lets a direct grant
in a resource-based policy stand without an identity Allow, while an account
grant delegates to the account's own policies ("How AWS enforcement code
logic evaluates requests to allow or deny access",
`reference_policies_evaluation-logic_policy-eval-denyallow.html`); applying
that rule is the caller's.

**Resource-based policies with identity-based ones**
(`reference_policies_evaluation-logic_policy-eval-denyallow.html`,
`reference_policies_evaluation-logic.html`,
`reference_policies_evaluation-logic_policy-eval-basics.html`,
`reference_policies_evaluation-logic-cross-account.html`). `Authorize`
decides in this order:

1. An identity-based Deny that applies denies (`IdentityDeny`), then a
   resource-based Deny (`ResourceDeny`): "If the enforcement code finds even
   one explicit deny that applies, the enforcement code returns a final
   decision of Deny." When both deny, AWS names "only one of those policy
   types" (`troubleshoot_access-denied.html`) without saying which; naming
   the identity-based one is this package's choice.
2. Within one account (`Caller.AccountID` is `ResourceAccount`), an
   identity-based Allow allows ("If either the identity-based policy or the
   resource-based policy within the same account allows the request and the
   other doesn't, the request is still allowed."), and so does a direct
   resource-based Allow: one that names the caller by `"*"`, its user ARN or
   ID, its role's ARN or ID, or its session ARN. "If a resource-based policy
   grants permission directly to the IAM user or the session principal that
   is making the request, then an implicit deny in an identity-based policy
   ... does not impact the final decision." A grant to a role ARN reaches
   the role's sessions ("You can specify the role ARN in the Principal
   element ... the principal that makes the request is the IAM role
   session") and is "limited by an implicit deny in a permissions boundary
   or session policy", not by the identity-based policies; neither limit is
   evaluated here, so the grant stands alone. A grant that names the caller
   only by its account ID or root ARN "delegates authority to the account"
   (`reference_policies_elements_principal.html`) and also needs an
   identity-based Allow. Otherwise the reason is `NoIdentityAllow` (that AWS
   names the identity-based type here is this package's choice).
3. Across accounts, "The request is allowed only if both evaluations return
   a decision of Allow": an identity-based Allow (else `NoIdentityAllow`)
   and a resource-based Allow of any kind (else `NoResourceAllow`). A
   `"*"` grant reaches another account's principals only with "identity-based
   permissions in their account". A `ResourceAccount` that is not a 12-digit
   ID is never the caller's account, so both allows are needed.

Before reading any policy, `Authorize` refuses these requests with
`ImplicitDeny` and `NoIdentityAllow`, each this package's choice:

- A `Caller` whose fields disagree. `AccountID` must be 12 digits and the
  account of `ARN`, an IAM or STS ARN with a blank region. By `Type`:
  `Account` needs `ARN` exactly `arn:P:iam::AccountID:root`, `PrincipalARN`
  equal to it and `UserID` the account ID; `User` needs an IAM user ARN,
  `PrincipalARN` equal to it and an `AIDA...` `UserID`; `AssumedRole` needs
  `arn:P:sts::AccountID:assumed-role/NAME/SESSION`, a `PrincipalARN` that
  is empty or a role ARN of the same partition and account whose name is
  `NAME`, and a `UserID` of `AROA...:SESSION`. Any other `Type` is
  refused. Matching and the root rule rely on these fields agreeing.
- A caller of another partition than the resource, when `Resource` is an
  ARN: "You cannot delegate access between accounts in different
  partitions." (`reference_identifiers.html`). A resource that is not an
  ARN, such as `"*"`, has no partition and refuses no caller; principal
  matching uses only the caller's partition.
- A session whose role was deleted (`AssumedRole` with an empty
  `PrincipalARN`). Without `aws:PrincipalArn` a Deny keyed on the role's
  ARN would not apply to it, and identity refuses it everything but
  GetCallerIdentity.

The root user (`PrincipalTypeAccount`) has an identity-based Allow without
policies ("with the exception of the AWS account root user, which has full
access"), so another account's root needs only the resource-based grant.
`Authorize` applies no other root rule: a service that never evaluates its
own account's root keeps doing so before calling it. A resource-based Deny
does apply to a root caller passed in.

**Resource-based principals** (`reference_policies_elements_principal.html`,
`reference_identifiers.html`). A resource-based statement applies when its
action, resource and conditions match and its `Principal` names the caller
(or its `NotPrincipal` does not exempt it). A statement without a
`Principal` or `NotPrincipal`, or without a `Resource` or `NotResource`,
never applies, and the identity side never applies a statement with a
`Principal`. Values match as follows, by ARN, names case-sensitively:

- `"*"` and `{"AWS":"*"}`: every caller, directly.
- An account ID or `arn:PARTITION:iam::ACCOUNT:root`: every caller of that
  account, through the account. An account ID matches a caller whose
  `AccountID` it is; a root ARN, a caller whose `ARN` has its partition and
  account. Neither depends on the request's resource, which need not be an
  ARN (`"*"` for ListBuckets, ListQueues or ListSecrets), so an account Deny
  applies there too.
- `arn:...:iam::ACCOUNT:user/PATH/NAME`: the IAM user with that `ARN`.
- `arn:...:iam::ACCOUNT:role/PATH/NAME`: a role session whose
  `PrincipalARN` is that ARN, path included (a role ARN is
  `role/role-name-with-path`, `reference_identifiers.html`).
- `arn:...:sts::ACCOUNT:assumed-role/NAME/SESSION`: the session with that
  `ARN`.
- `AIDA...`: the IAM user with that `UserID`; `AROA...`: a session of that
  role, whose `UserID` is `<role ID>:<session name>` ("You can create
  resource-based policies that grant access by unique ID";
  `reference_identifiers.html`). The format accepted at parse, upper-case
  letters and digits, 16 to 128 characters (the IAM API's `UserId` and
  `RoleId` lengths), is this package's choice.
- Service, CanonicalUser and federated-user values match no caller.
- **A session whose role was deleted** is refused before matching (see
  above). Matching keeps the rule tule.dev/sigv4 v0.4.1 states for
  `Principal.PrincipalARN` as a second guard: nothing that names the role
  (role ARN, session ARN, role ID) matches such a session. AWS reaches the
  same end through unique IDs: "if you delete the role, then you break the
  relationship. The policy no longer applies".

`NotPrincipal` (`reference_policies_elements_notprincipal.html`): "When you
use NotPrincipal, you must also specify the account ARN of the not-denied
principal. Otherwise, the policy might deny access to the entire account
... AWS might validate the account first, then the role, and then the
assumed-role user. ... we strongly recommend that you explicitly include
the ARN for a user's account, or include both the ARN for a role and the
ARN for the account containing that role." AWS leaves the exact rule to
each service. This package's choice is the strict reading of that
recommendation. The caller is exempt from the Deny when the element is
`"*"`, or when it names the caller's account (by account ID or root ARN)
and also:

- for the root user, nothing more;
- for an IAM user, that user, by its ARN or `AIDA...` ID;
- for a role session, the role, by its ARN or `AROA...` ID. The session's
  own ARN does not count: it names the session, not the role.

So `NotPrincipal` with a user ARN alone, a role ARN alone, or the account
and a session ARN, denies that user or session.

**Request context in `Authorize`.** `aws:PrincipalArn`,
`aws:PrincipalAccount`, `aws:userid`, `aws:PrincipalType` and
`aws:username` come from the `Caller` (`PrincipalARN`, `AccountID`,
`UserID`, `Type`, and for an IAM user the last element of `ARN`) and
replace any value `Context` gives them. `aws:username` is absent for other
callers ("present for IAM users only"; `reference_policies_variables.html`).
That is this package's choice, so that a caller's identity keys cannot be
set through the request context. `aws:PrincipalTag/*` and every other key
come from `Context` only.

**Matching cost.** Wildcard patterns are matched by simulating the pattern
as an automaton, in O(pattern × input) time and O(pattern) space whatever
the number of wildcards; no input backtracks exponentially. A condition
compares every request value with every policy value, so `Evaluate`'s cost
grows with the context's size times the policies' (2000 request values of
200 characters against 2000 `StringLike` patterns took about 11 seconds in
testing). Policy size matters the same way: a review measured 22 seconds
for one evaluation of 50 statements in an 800KB resource-based policy.
Profiling the same shape here (50 statements of about 16KB of `a*`
wildcards, 804KB in all) put over 90% of the time in matching, which
grows with the resource's length (75 ms for a 100-character resource, 790
ms for a 1024-character one), and almost none in compiling patterns, so
patterns are not precompiled at parse. Services must cap the request
context they pass, in number of keys and values and in value length, and
cap policy size, as AWS caps each resource-based policy ("Bucket policies
are limited to 20 KB in size."; S3 User Guide,
`https://docs.aws.amazon.com/AmazonS3/latest/userguide/add-bucket-policy.html`).

## Parse error messages

IAM documents the MalformedPolicyDocument error but not its messages
(`https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutUserPolicy.html`).
The messages below are IAM's as reproduced by the moto project's IAM policy
validation tests (`tests/test_iam/test_iam_policies.py`), a secondary source:
`Syntax errors in policy.`, `The policy failed legacy parsing` (an `Effect`
in the wrong case), `Policy statement must contain actions.`, `Policy
statement must contain resources.`, `Actions/Conditions must be prefaced by
a vendor, e.g., iam, sdb, ec2, etc.`, `Actions/Condition can contain only one
colon.`, `Vendor X is not valid`, `Resource X must be in ARN format or "*".`,
`Resource vendor must be fully qualified and cannot contain regexes.` and
`Statement IDs (SID) in a single policy must be unique.` `Invalid principal
in policy`, `Policy document should not specify a principal.` and `Has
prohibited field Resource` are IAM's messages as reported by users; this
package uses the last form for `NotResource` and `NotPrincipal` in a trust
policy too. `Missing required field Principal.` follows the form of the
reported `Missing required field Effect.`
`Missing required field Effect.` is S3's reported message for the same
fault. These are this package's own wording: `Statement IDs (SID) must
contain only alphanumeric characters.`, `NotPrincipal must be used with
"Effect":"Deny".` (the NotPrincipal page's sentence), `Condition operator X
is not valid.` and `Condition value X is not valid for OPERATOR.`; IAM's
text for those faults is not documented.

## Known gaps

- Permissions boundaries, session policies, SCPs and RCPs are not
  evaluated, by `Authorize` or otherwise. Where AWS lets them limit a
  resource-based grant (a grant to a role ARN, or one through
  `aws:PrincipalArn`), the grant here is unlimited.
- AWS converts a user or role ARN in a stored resource-based policy to the
  principal's unique ID, so a principal recreated under the same name does
  not inherit the grant. `Authorize` matches by ARN, so a recreated user or
  role does inherit it, until identity can resolve unique IDs for the
  services. A session whose role was deleted is the exception: `Authorize`
  refuses it.
- `aws:PrincipalOrgID` and `aws:PrincipalOrgPaths` are not supplied
  (identity does not carry the organization), so a condition on them never
  holds, and a negated one always does.
- Service principals never match a Tule caller, and neither do
  CanonicalUser or federated-user values; S3 ACL grantees are not
  evaluated.
- Some services require an explicit resource-based Allow within one
  account ("Resource-based policies for services other than IAM and AWS KMS
  may also require an explicit Allow statement within the same account";
  `reference_policies_evaluation-logic_policy-eval-denyallow.html`);
  `Authorize` applies the general rule, and such a service must check
  `Authorization.Resource` itself.
- Root-user exceptions that a service makes to its resource-based
  policies are the service's to apply.
- Actions are not checked against a service's real action list, and a
  resource's applicability to an action is not known: `NotAction` with
  `Resource: "*"` covers every action of every service.
- Element names are matched case-sensitively and operator names exactly; the
  User Guide does not say whether IAM accepts other casings.
- `Id` is accepted in any policy, `ParseIdentity` included, though the
  grammar notes say an identity-based policy must not have one; IAM's
  message for it is not known.
- Empty value arrays in `Condition` are rejected; IAM's handling is not
  documented.
- IAM's per-service ARN checks (no region in an IAM or S3 ARN, IAM resource
  path prefixes, partition names) are not applied.
- A multivalued key used without a set operator matches when any value
  matches; the User Guide requires a set operator and does not define this
  case.
- Context keys that differ only by case are merged into one key with all
  their values.
- An all-digits date is epoch seconds, so the W3C year-only form (`YYYY`) is
  not available. Epoch seconds outside years 0000 to 9999 are invalid.
- Principals match by ARN, not by unique ID. IAM turns a user or role ARN
  in a trust policy into the principal's unique ID when the policy is
  saved, so deleting and recreating a user or role with the same name
  breaks the grant ("AWS JSON policy elements: Principal"). Here the
  recreated principal matches the old ARN. A caller that needs AWS's
  recreate semantics must bind ARNs to unique IDs itself when a policy is
  saved, and rewrite stale bindings to values that match nothing before
  calling `TrustMatch`.
- Role and user names in ARNs match case-sensitively, in principals as in
  resources, as the User Guide says of user names ("the user name part of
  the ARN is case sensitive"). It does not say whether role names compare
  the same way, so a role named `Admin` in a trust policy does not match a
  session of `admin` here.
- A role ARN with a path matches its sessions by name, since a session ARN
  carries no path. The `aws:PrincipalArn` this package derives from a
  session ARN is only a fallback, without the path: AWS's value for a role
  session is the role ARN with its path, so a path-scoped condition (such as
  a Deny on `arn:aws:iam::*:role/restricted/*`) does not apply to the
  derived value. Callers must pass `aws:PrincipalArn` in the context for
  role sessions.
- `aws:userid` for principals other than the root user comes from the
  context only.
- The Bool operator replaces policy variables, following the operators page;
  the variables page lists Boolean among the operators without them.

## Development

```sh
make fmt    # format
make lint   # golangci-lint, v2.15.0 in CI
make test   # go test -race ./...
go test -run '^$' -fuzz '^FuzzParse$' -fuzztime 30s
# also FuzzGlob, FuzzEvaluate, FuzzJunkNeverGrants, FuzzParseResource,
# FuzzAuthorize and FuzzConformanceParse
```

## License

MIT; see [LICENSE](LICENSE).
