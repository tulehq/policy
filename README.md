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
p, err := policy.Parse(doc)
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

ok := policy.AllowsPrincipal(trust, "sts:AssumeRole", callerARN, ctx)
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
  (a statement needs a `Resource` only when it has no `Principal`).
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
- `TrustMatch(trust *Policy, action, principalARN string, ctx
  map[string][]string) TrustResult`, with `TrustResult{Decision Decision;
  Direct bool; Sid string}`. `Direct` is true when an allowing statement
  named the caller other than through its account.
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
when its action, resource and every condition match. `Principal` and
`NotPrincipal` are ignored by `Evaluate`, since an identity-based policy has
none (`reference_policies_elements_principal.html`). A statement with no
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
  operators a key whose only value is `""` counts as missing. `Null` with
  `true` holds when the key is absent, with `false` when present.
- `ForAnyValue` holds when at least one request value passes, `ForAllValues`
  when all do; a value passes a negated operator when it matches no policy
  value.
- Numbers are decimal (sign, digits, fraction, exponent) and compared as
  float64. Dates are the W3C ISO 8601 profile or epoch seconds. IP values are
  CIDR, a bare address being /32 (or /128 for IPv6). Binary values are
  base64 on both sides, compared decoded. `ArnLike` checks the six fields
  separately, each with `*` and `?`.
- **Malformed conditions are refused at Parse.** An unknown operator
  (including any spelling other than the documented one, and any unknown
  prefix or suffix combination) is a parse error, as is a policy value that
  cannot be valid for its operator: not a number for Numeric, not a date for
  Date, not an address or CIDR for IpAddress, not base64 for BinaryEquals,
  not `true`/`false` for Bool or Null, not an ARN of six fields for the ARN
  operators. A Bool or ARN value holding a policy variable is checked only
  at evaluation. A Deny statement in a parsed policy therefore fails to
  apply only because the request lacks a key or its values do not match,
  never because the policy is malformed.
- **Malformed request values never grant and always deny.** A request
  value that is invalid for its operator (`"abc"` for a Numeric operator, a
  non-ARN for an ARN operator, an epoch outside years 0000 to 9999 for a
  Date operator) is neither a match nor a non-match: it takes the result
  worse for the caller. In an Allow statement it never helps the condition
  hold; in a Deny statement it always counts toward the condition holding.
  This holds under every operator, plain, negated, `ForAnyValue` and
  `ForAllValues`, while the key's valid values are compared as usual, so
  appending a junk value can neither switch a Deny off nor switch an Allow
  on. A policy value that a variable turns invalid follows the same rule.
  AWS documents neither case; this is a deliberate choice.

**Trust policies** (`reference_policies_elements_principal.html`,
`..._notprincipal.html`). `AllowsPrincipal` applies the same deny-wins logic
to statements whose action matches, whose `Principal` names the caller (or
whose `NotPrincipal` does not), and whose conditions hold; `Resource` is
ignored. `"*"` and `{"AWS":"*"}` match anyone. An account ID or
`arn:...:iam::ACCOUNT:root` matches every principal of the account. A role
ARN matches the role's sessions (`arn:...:sts::ACCOUNT:assumed-role/NAME/...`,
by partition, account and name, so a role path does not matter) and a caller
whose `aws:PrincipalArn` is that ARN. Other values (user, session,
federated-user ARNs, `Service`, `Federated`, `CanonicalUser`) match exactly.
Partial wildcards in principals are rejected.

`TrustMatch` also reports whether the Allow is direct: by `"*"`, or by the
caller's own user, role or role-session ARN (or service, federated or
canonical user identifier), rather than only by an account ID or root ARN.
Its `Sid` is the first direct allowing statement's, else the first allowing
statement's. AWS lets a direct grant in a resource-based policy stand
without an identity Allow within the account, while an account grant
delegates to the account's own policies ("How AWS enforcement code logic
evaluates requests to allow or deny access",
`reference_policies_evaluation-logic_policy-eval-denyallow.html`); applying
that rule is the caller's.

**Matching cost.** Wildcard patterns are matched by simulating the pattern
as an automaton, in O(pattern × input) time and O(pattern) space whatever
the number of wildcards; no input backtracks exponentially.

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
- Numbers compare as float64, so integers beyond 2^53 lose precision.
- A role ARN with a path is matched against its sessions by name; the role
  ARN derived for `aws:PrincipalArn` from a session ARN has no path. Pass
  `aws:PrincipalArn` in the context for roles with paths.
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
