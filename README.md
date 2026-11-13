# policy

A Go library that parses AWS IAM policy documents and evaluates requests
against them with the logic AWS applies to identity-based policies within
one account, for the Tule services that stand in for AWS ones. It also
evaluates role trust policies for AssumeRole.

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
- `ParseError{Message string}`, returned by `Parse` as `*ParseError`.

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
account ID, an IAM or STS ARN, or `"*"`; `Service` a service principal such
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

**Matching cost.** Wildcard patterns are matched by simulating the pattern
as an automaton, in O(pattern × input) time and O(pattern) space whatever
the number of wildcards; no input backtracks exponentially. A condition
compares every request value with every policy value, so `Evaluate`'s cost
grows with the context's size times the policies' (2000 request values of
200 characters against 2000 `StringLike` patterns took about 11 seconds in
testing). Services must cap the
request context they pass, in number of keys and values and in value
length, as they cap policy size.

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

- Only identity-based policies within one account and trust policies.
  Resource-based policies, permissions boundaries, session policies, SCPs,
  RCPs and cross-account evaluation are not implemented.
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
go test -run '^$' -fuzz FuzzParse -fuzztime 30s    # also FuzzGlob, FuzzEvaluate
```

## License

MIT; see [LICENSE](LICENSE).
