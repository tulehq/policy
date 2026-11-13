package policy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParseError is a policy document that Parse rejects. Its message is the
// text IAM returns with a MalformedPolicyDocument error for the same fault
// where that text is known, so a service can return it as IAM would. IAM's
// API reference documents the error ("The request was rejected because the
// policy document was malformed. The error message describes the specific
// error."; https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutUserPolicy.html)
// but not its messages; the README lists where each one comes from.
type ParseError struct {
	Message string
}

func (e *ParseError) Error() string { return e.Message }

// Messages. The README says which come from IAM and which are this
// package's own.
const (
	msgSyntax          = "Syntax errors in policy."
	msgLegacy          = "The policy failed legacy parsing"
	msgNoEffect        = "Missing required field Effect."
	msgNoActions       = "Policy statement must contain actions."
	msgNoResources     = "Policy statement must contain resources."
	msgVendor          = "Actions/Conditions must be prefaced by a vendor, e.g., iam, sdb, ec2, etc."
	msgOneColon        = "Actions/Condition can contain only one colon."
	msgVendorInvalid   = "Vendor %s is not valid"
	msgResourceARN     = "Resource %s must be in ARN format or \"*\"."
	msgResourceVendor  = "Resource vendor must be fully qualified and cannot contain regexes."
	msgSidUnique       = "Statement IDs (SID) in a single policy must be unique."
	msgSidChars        = "Statement IDs (SID) must contain only alphanumeric characters."
	msgPrincipal       = "Invalid principal in policy"
	msgNotPrincipalEff = "NotPrincipal must be used with \"Effect\":\"Deny\"."
	msgOperator        = "Condition operator %s is not valid."
	msgHasPrincipal    = "Policy document should not specify a principal."
	msgNoPrincipal     = "Missing required field Principal."
	msgProhibited      = "Has prohibited field %s"
	msgConditionValue  = "Condition value %s is not valid for %s."
)

func parseErr(format string, args ...any) *ParseError {
	if len(args) == 0 {
		return &ParseError{Message: format}
	}
	return &ParseError{Message: fmt.Sprintf(format, args...)}
}

// Policy is a parsed policy document. It is immutable and safe for
// concurrent use.
type Policy struct {
	statements []statement
	// vars is whether policy variables are replaced: true for Version
	// 2012-10-17 only.
	vars bool
}

type effect uint8

const (
	effectAllow effect = iota
	effectDeny
)

type statement struct {
	sid string

	// principal is nil when the statement has neither Principal nor
	// NotPrincipal.
	principal *principals

	actions []pattern

	// resources holds the raw Resource or NotResource entries; they are
	// compiled per request because they may hold policy variables.
	resources []string

	conditions []condition

	effect       effect
	notPrincipal bool
	notAction    bool
	notResource  bool
	// hasResource is false when the statement has neither Resource nor
	// NotResource; it then applies to no resource.
	hasResource bool
}

// Parse parses an IAM policy document of either kind, identity-based or
// role trust, without enforcing either kind's element rules: a statement
// may have a Principal or not, and needs a Resource only when it has no
// Principal or NotPrincipal. ParseIdentity and ParseTrust enforce the rules
// of one kind. The grammar is the IAM User Guide's "Grammar of the IAM
// JSON policy language"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html)
// and its element reference
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html).
// Element names are matched exactly. A rejected document returns a
// *ParseError. Parse applies no size limit; that is the caller's.
func Parse(doc []byte) (*Policy, error) { return parse(doc, kindAny) }

// docKind is the kind of policy a document is parsed as.
type docKind uint8

const (
	// kindAny is Parse's lenient kind.
	kindAny docKind = iota
	// kindTrust is a role trust policy.
	kindTrust
	// kindResource is a resource-based policy.
	kindResource
)

// parse parses doc as a policy of kind k. A trust or resource-based kind
// lets a statement omit Resource even without a Principal, so that
// ParseTrust and ParseResource can report the missing Principal instead,
// and the resource-based kind takes the principal values of resource-based
// policies (see checkPrincipalIDs).
func parse(doc []byte, k docKind) (*Policy, error) {
	v, err := decodeJSON(doc)
	if err != nil {
		return nil, parseErr(msgSyntax)
	}
	obj, ok := v.(object)
	if !ok {
		return nil, parseErr(msgSyntax)
	}
	p := &Policy{}
	stmts, err := parseTopLevel(p, obj)
	if err != nil {
		return nil, err
	}
	if p.statements, err = parseStatements(stmts, p.vars, k); err != nil {
		return nil, err
	}
	return p, nil
}

// ParseIdentity parses an identity-based policy: Parse, and no statement
// may have a Principal or NotPrincipal ("You cannot use the Principal
// element in an identity-based policy."; "AWS JSON policy elements:
// Principal",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html;
// "You cannot use the NotPrincipal element in an IAM identity-based
// policy"; "AWS JSON policy elements: NotPrincipal"). Each statement then
// needs a Resource or NotResource, as Parse already requires of a statement
// without a Principal.
func ParseIdentity(doc []byte) (*Policy, error) {
	p, err := Parse(doc)
	if err != nil {
		return nil, err
	}
	for _, s := range p.statements {
		if s.principal != nil {
			return nil, parseErr(msgHasPrincipal)
		}
	}
	return p, nil
}

// ParseTrust parses a role trust policy: Parse, and every statement needs
// a Principal and may have no Resource, NotResource or NotPrincipal. "In
// IAM roles, use the Principal element in the role trust policy to specify
// who can assume the role." (Principal page); "You cannot use the
// NotPrincipal element in an IAM identity-based policy nor in an IAM role
// trust policy." (NotPrincipal page). A trust policy names no resource: it
// is attached to the role it governs.
func ParseTrust(doc []byte) (*Policy, error) {
	p, err := parse(doc, kindTrust)
	if err != nil {
		return nil, err
	}
	for _, s := range p.statements {
		switch {
		case s.principal == nil:
			return nil, parseErr(msgNoPrincipal)
		case s.notPrincipal:
			return nil, parseErr(msgProhibited, "NotPrincipal")
		case s.hasResource && s.notResource:
			return nil, parseErr(msgProhibited, "NotResource")
		case s.hasResource:
			return nil, parseErr(msgProhibited, "Resource")
		}
	}
	return p, nil
}

// ParseResource parses a resource-based policy, such as a bucket, queue,
// secret or function policy: Parse, and every statement needs a Principal
// or NotPrincipal ("You must use the Principal element in resource-based
// policies."; Principal page) and a Resource or NotResource ("Statements
// must include either a Resource or a NotResource element."; "IAM JSON
// policy elements: Resource"). A missing Principal is reported before a
// missing Resource. NotPrincipal needs "Effect":"Deny", as in Parse.
//
// Principal values are those of resource-based policies: besides what
// ParseTrust accepts, an AWS value may be the unique ID of an IAM user
// (AIDA...) or role (AROA...) ("You can create resource-based policies
// that grant access by unique ID"; "IAM identifiers",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html),
// and Federated is refused: "OIDC federated principals are not supported
// in policy types other than role trust policies." (Principal page). The
// page describes SAML federated principals for role trust policies only;
// refusing them here too is this package's choice.
//
// Services may layer their own checks, such as S3's requirement that
// Resource name the bucket.
func ParseResource(doc []byte) (*Policy, error) {
	p, err := parse(doc, kindResource)
	if err != nil {
		return nil, err
	}
	for _, s := range p.statements {
		switch {
		case s.principal == nil:
			return nil, parseErr(msgNoPrincipal)
		case !s.hasResource:
			return nil, parseErr(msgNoResources)
		}
	}
	return p, nil
}

// parseTopLevel reads the policy's Version, Id and Statement elements and
// returns the Statement element's value.
func parseTopLevel(p *Policy, obj object) (any, error) {
	var stmts any
	hasStatement := false
	for _, m := range obj {
		switch m.name {
		case "Version":
			vars, err := parseVersion(m.value)
			if err != nil {
				return nil, err
			}
			p.vars = vars
		case "Id":
			if _, ok := m.value.(string); !ok {
				return nil, parseErr(msgSyntax)
			}
		case "Statement":
			stmts, hasStatement = m.value, true
		default:
			return nil, parseErr(msgSyntax)
		}
	}
	if !hasStatement {
		return nil, parseErr(msgSyntax)
	}
	return stmts, nil
}

// parseVersion accepts the two versions of the policy language ("IAM
// supports the following Version element values: 2012-10-17 ...
// 2008-10-17"; "IAM JSON policy elements: Version",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html).
// Without a Version the policy is 2008-10-17 ("The default policy version
// is "2008-10-17.""; "Troubleshoot IAM policies"), so it has no variables.
func parseVersion(v any) (bool, error) {
	switch v {
	case "2012-10-17":
		return true, nil
	case "2008-10-17":
		return false, nil
	default:
		return false, parseErr(msgSyntax)
	}
}

// parseStatements parses the Statement element, a statement object or a
// non-empty array of them. The grammar gives an array; the element
// reference's examples and the IAM User Guide's own policies also use a
// single object.
func parseStatements(v any, vars bool, k docKind) ([]statement, error) {
	list, isList := v.([]any)
	if !isList {
		list = []any{v}
	}
	if len(list) == 0 {
		return nil, parseErr(msgSyntax)
	}
	out := make([]statement, 0, len(list))
	sids := map[string]bool{}
	for _, item := range list {
		obj, ok := item.(object)
		if !ok {
			return nil, parseErr(msgSyntax)
		}
		s, err := parseStatement(obj, vars, k)
		if err != nil {
			return nil, err
		}
		if s.sid != "" {
			if sids[s.sid] {
				return nil, parseErr(msgSidUnique)
			}
			sids[s.sid] = true
		}
		out = append(out, s)
	}
	return out, nil
}

// rawStatement is a statement's elements before validation.
type rawStatement struct {
	fields map[string]any
	// vars is whether the policy's Version replaces policy variables.
	vars bool
	// kind is the kind of policy the document is parsed as.
	kind docKind
}

func (r rawStatement) get(name string) (any, bool) {
	v, ok := r.fields[name]
	return v, ok
}

// either returns whichever of two mutually exclusive elements is present,
// and whether it is the second.
func (r rawStatement) either(a, b string) (v any, second, present bool, err error) {
	va, okA := r.get(a)
	vb, okB := r.get(b)
	switch {
	case okA && okB:
		return nil, false, false, parseErr(msgSyntax)
	case okB:
		return vb, true, true, nil
	default:
		return va, false, okA, nil
	}
}

var statementElements = map[string]bool{
	"Sid": true, "Effect": true, "Principal": true, "NotPrincipal": true,
	"Action": true, "NotAction": true, "Resource": true, "NotResource": true,
	"Condition": true,
}

func parseStatement(obj object, vars bool, k docKind) (statement, error) {
	raw := rawStatement{fields: make(map[string]any, len(obj)), vars: vars, kind: k}
	for _, m := range obj {
		if !statementElements[m.name] {
			return statement{}, parseErr(msgSyntax)
		}
		raw.fields[m.name] = m.value
	}
	var s statement
	for _, step := range []func(*statement, rawStatement) error{
		parseSid, parseEffect, parsePrincipalElement, parseActionElement,
		parseResourceElement, parseConditionElement,
	} {
		if err := step(&s, raw); err != nil {
			return statement{}, err
		}
	}
	return s, nil
}

// parseSid: "For IAM policies, basic alphanumeric characters (A-Z,a-z,0-9)
// are the only allowed characters in the Sid value." ("Grammar of the IAM
// JSON policy language", sid_string). That rule is IAM's: a resource-based
// policy belongs to its service, whose Sids may be wider, such as the
// hyphens and underscores of an SQS AddPermission Label or a Lambda
// StatementId; the IAM User Guide's Sid element page leaves Sid rules for
// resource-based policies to services such as Amazon SQS and Amazon SNS.
// So a resource-based policy's Sid may be any string, unique within the
// policy, and the service applies its own rule.
func parseSid(s *statement, r rawStatement) error {
	v, ok := r.get("Sid")
	if !ok {
		return nil
	}
	sid, ok := v.(string)
	if !ok {
		return parseErr(msgSyntax)
	}
	if r.kind != kindResource && !isAlnumString(sid) {
		return parseErr(msgSidChars)
	}
	s.sid = sid
	return nil
}

// isAlnumString reports whether s holds only the characters IAM allows in
// a Sid, A-Z, a-z and 0-9.
func isAlnumString(s string) bool {
	for _, c := range []byte(s) {
		if !isAlnum(c) {
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// parseEffect: <effect_block> = "Effect" : ("Allow" | "Deny").
func parseEffect(s *statement, r rawStatement) error {
	v, ok := r.get("Effect")
	if !ok {
		return parseErr(msgNoEffect)
	}
	str, ok := v.(string)
	if !ok {
		return parseErr(msgSyntax)
	}
	switch str {
	case "Allow":
		s.effect = effectAllow
	case "Deny":
		s.effect = effectDeny
	default:
		return parseErr(msgLegacy)
	}
	return nil
}

// parseActionElement parses Action or NotAction. "Statements must include
// either an Action or NotAction element." ("IAM JSON policy elements:
// Action", https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html).
func parseActionElement(s *statement, r rawStatement) error {
	v, not, present, err := r.either("Action", "NotAction")
	if err != nil {
		return err
	}
	if !present {
		return parseErr(msgNoActions)
	}
	list, err := stringList(v)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		return parseErr(msgNoActions)
	}
	s.notAction = not
	s.actions = make([]pattern, 0, len(list))
	for _, a := range list {
		if err := checkAction(a); err != nil {
			return err
		}
		s.actions = append(s.actions, globPattern(a))
	}
	return nil
}

// checkAction checks an action_string: "Consists of a service namespace, a
// colon, and the name of an action. Action names can include wildcards."
// ("Grammar of the IAM JSON policy language"), or "*".
func checkAction(a string) error {
	if a == "*" {
		return nil
	}
	vendor, name, ok := strings.Cut(a, ":")
	if !ok {
		return parseErr(msgVendor)
	}
	if strings.Contains(name, ":") {
		return parseErr(msgOneColon)
	}
	if !validVendor(vendor) {
		return parseErr(msgVendorInvalid, vendor)
	}
	return nil
}

func validVendor(v string) bool {
	if v == "" {
		return false
	}
	for _, c := range []byte(v) {
		if !isAlnum(c) && c != '-' && c != '_' && c != '*' && c != '?' {
			return false
		}
	}
	return true
}

// parseResourceElement parses Resource or NotResource. "Statements must
// include either a Resource or a NotResource element." ("IAM JSON policy
// elements: Resource",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html).
// A role trust policy names the role by being attached to it and has no
// Resource, so a statement with a Principal or NotPrincipal may omit it.
func parseResourceElement(s *statement, r rawStatement) error {
	v, not, present, err := r.either("Resource", "NotResource")
	if err != nil {
		return err
	}
	if !present {
		if s.principal == nil && r.kind == kindAny {
			return parseErr(msgNoResources)
		}
		return nil
	}
	list, err := stringList(v)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		return parseErr(msgNoResources)
	}
	for _, res := range list {
		if err := checkResource(res); err != nil {
			return err
		}
	}
	s.resources, s.notResource, s.hasResource = list, not, true
	return nil
}

// checkResource checks a resource_string: an ARN or "*". "You can't use a
// wildcard in the service segment that identifies the AWS product."
// ("IAM JSON policy elements: Resource").
func checkResource(res string) error {
	if res == "*" {
		return nil
	}
	if !strings.HasPrefix(res, "arn:") {
		return parseErr(msgResourceARN, res)
	}
	f := strings.SplitN(res, ":", 4)
	if len(f) < 3 || f[2] == "" || strings.ContainsAny(f[2], "*?") {
		return parseErr(msgResourceVendor)
	}
	return nil
}

// parseConditionElement parses Condition:
// "Condition" : { "condition-operator" : { "condition-key" : "condition-value" }}
// ("IAM JSON policy elements: Condition",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html).
// A value is a string, number or boolean, or a non-empty array of them.
//
// An unknown operator, and a value that cannot be valid for its operator
// (see checkConditionValue), are rejected here rather than left to fail at
// evaluation: a condition that could never hold would make a Deny statement
// silently deny nothing. So a Deny statement in a parsed policy fails to
// apply only because the request lacks a key or its values do not match,
// never because the policy is malformed.
func parseConditionElement(s *statement, r rawStatement) error {
	v, ok := r.get("Condition")
	if !ok {
		return nil
	}
	ops, ok := v.(object)
	if !ok {
		return parseErr(msgSyntax)
	}
	for _, opm := range ops {
		keys, ok := opm.value.(object)
		if !ok {
			return parseErr(msgSyntax)
		}
		op, known := parseOperator(opm.name)
		if !known {
			return parseErr(msgOperator, opm.name)
		}
		for _, km := range keys {
			values, err := conditionValues(km.value)
			if err != nil {
				return err
			}
			for _, v := range values {
				if !checkConditionValue(op.base, v, r.vars) {
					return parseErr(msgConditionValue, v, opm.name)
				}
			}
			s.conditions = append(s.conditions, condition{op: op, key: km.name, values: values})
		}
	}
	return nil
}

func conditionValues(v any) ([]string, error) {
	list, isList := v.([]any)
	if !isList {
		list = []any{v}
	}
	if len(list) == 0 {
		return nil, parseErr(msgSyntax)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		switch x := item.(type) {
		case string:
			out = append(out, x)
		case json.Number:
			out = append(out, x.String())
		case bool:
			out = append(out, fmt.Sprint(x))
		default:
			return nil, parseErr(msgSyntax)
		}
	}
	return out, nil
}

// stringList reads an element that is a string or an array of strings.
func stringList(v any) ([]string, error) {
	switch x := v.(type) {
	case string:
		return []string{x}, nil
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			s, ok := item.(string)
			if !ok {
				return nil, parseErr(msgSyntax)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, parseErr(msgSyntax)
	}
}
