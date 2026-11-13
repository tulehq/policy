package policy

import (
	"strings"
)

// Condition operators follow the IAM User Guide's "IAM JSON policy
// elements: Condition operators"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html),
// "Single-valued vs. multivalued context keys"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html)
// and "Conditions with multiple context keys or values"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-logic-multiple-context-keys-or-values.html).

// valueKind is the family of a base condition operator.
type valueKind uint8

const (
	kindString valueKind = iota
	kindStringFold
	kindStringLike
	kindNumeric
	kindDate
	kindBool
	kindBinary
	kindIP
	kindARN
	kindNull
)

// order is the comparison a Numeric or Date operator makes between the
// request's value and the policy's.
type order uint8

const (
	orderEq order = iota
	orderLt
	orderLe
	orderGt
	orderGe
)

// baseOp is a condition operator without its set or IfExists qualifiers.
type baseOp struct {
	kind valueKind
	// negated operators match when no policy value matches; across a key's
	// policy values that is a NOR ("If a single negated matching condition
	// operator includes multiple values for a context key, those values are
	// evaluated using a logical NOR."; "Conditions with multiple context
	// keys or values").
	negated bool
	order   order
}

// vars reports whether policy variables are replaced in the operator's
// values. The operators page lists policy variables as supported for the
// String, Boolean and ARN operators and not for Numeric, Date, Binary or IP
// address; Null takes none ("You can not use a policy variable with the
// Null condition operator."). The variables page omits Boolean; this
// follows the operators page, which is the one that defines each operator.
func (b baseOp) vars() bool {
	switch b.kind {
	case kindString, kindStringFold, kindStringLike, kindARN, kindBool:
		return true
	default:
		return false
	}
}

// baseOps is every base operator the operators page documents. The page
// says ArnEquals and ArnLike "behave identically", as do ArnNotEquals and
// ArnNotLike.
var baseOps = map[string]baseOp{
	"StringEquals":              {kind: kindString},
	"StringNotEquals":           {kind: kindString, negated: true},
	"StringEqualsIgnoreCase":    {kind: kindStringFold},
	"StringNotEqualsIgnoreCase": {kind: kindStringFold, negated: true},
	"StringLike":                {kind: kindStringLike},
	"StringNotLike":             {kind: kindStringLike, negated: true},
	"NumericEquals":             {kind: kindNumeric},
	"NumericNotEquals":          {kind: kindNumeric, negated: true},
	"NumericLessThan":           {kind: kindNumeric, order: orderLt},
	"NumericLessThanEquals":     {kind: kindNumeric, order: orderLe},
	"NumericGreaterThan":        {kind: kindNumeric, order: orderGt},
	"NumericGreaterThanEquals":  {kind: kindNumeric, order: orderGe},
	"DateEquals":                {kind: kindDate},
	"DateNotEquals":             {kind: kindDate, negated: true},
	"DateLessThan":              {kind: kindDate, order: orderLt},
	"DateLessThanEquals":        {kind: kindDate, order: orderLe},
	"DateGreaterThan":           {kind: kindDate, order: orderGt},
	"DateGreaterThanEquals":     {kind: kindDate, order: orderGe},
	"Bool":                      {kind: kindBool},
	"BinaryEquals":              {kind: kindBinary},
	"IpAddress":                 {kind: kindIP},
	"NotIpAddress":              {kind: kindIP, negated: true},
	"ArnEquals":                 {kind: kindARN},
	"ArnLike":                   {kind: kindARN},
	"ArnNotEquals":              {kind: kindARN, negated: true},
	"ArnNotLike":                {kind: kindARN, negated: true},
	"Null":                      {kind: kindNull},
}

// setOp is the ForAllValues: or ForAnyValue: qualifier.
type setOp uint8

const (
	setNone setOp = iota
	setForAll
	setForAny
)

// operator is a parsed condition operator name.
type operator struct {
	set      setOp
	ifExists bool
	base     baseOp
}

// parseOperator parses a condition operator name, and reports false for a
// name this package does not implement. Names are matched exactly, as the
// operators page spells them.
//
// "You can add IfExists to the end of any condition operator name except
// the Null condition" (operators page, "...IfExists condition operators").
// ForAllValues: and ForAnyValue: qualify any operator but Null, which tests
// whether a key is present rather than its values.
func parseOperator(name string) (operator, bool) {
	op := operator{}
	rest := name
	if r, ok := strings.CutPrefix(rest, "ForAllValues:"); ok {
		op.set, rest = setForAll, r
	} else if r, ok := strings.CutPrefix(rest, "ForAnyValue:"); ok {
		op.set, rest = setForAny, r
	}
	base, ok := baseOps[rest]
	if !ok {
		trimmed, cut := strings.CutSuffix(rest, "IfExists")
		base, ok = baseOps[trimmed]
		ok = ok && cut && trimmed != "Null"
		op.ifExists = true
	}
	if !ok || (base.kind == kindNull && op.set != setNone) {
		return operator{}, false
	}
	op.base = base
	return op, true
}

// condition is one condition key under one operator, with its policy
// values.
type condition struct {
	key    string
	values []string
	op     operator
}

// holds evaluates the condition against the request.
//
// A key's policy values are ORed ("If a single condition operator includes
// multiple values for a context key, those values are evaluated using a
// logical OR."), and a negated operator holds when none matches.
//
// A missing key: "If the key that you specify in a policy condition is not
// present in the request context, the values do not match and the
// condition is false. If the policy condition requires that the key is not
// matched, such as StringNotLike or ArnNotLike, and the right key is not
// present, the condition is true. This logic applies to all condition
// operators except ...IfExists and Null check." With IfExists, "If the key
// is not present, evaluate the condition element as true." ForAllValues
// "also returns true if there are no context keys in the request", and
// ForAnyValue returns false "if the key does not exist". For both set
// operators an empty-string value is no value, and a key whose values are
// all empty strings is a missing key:
// ForAllValues "returns true if there are no context keys in the request
// or if the context key value resolves to a null dataset, such as an empty
// string."
//
// Malformed request values never grant and always deny. A request value
// that is not valid for the operator, such as "abc" for a Numeric
// operator, is neither a match nor a non-match: it takes whichever result
// is worse for the caller. In an Allow statement (deny false) it never
// helps the condition hold; in a Deny statement (deny true) it always
// counts toward the condition holding. Because every operator's result
// only rises or only falls as one value's match does, setting the value to
// the operator's negation for Allow, and its opposite for Deny, gives that
// worst case under every operator, plain, negated, ForAnyValue or
// ForAllValues. The key's other, valid values are compared as usual, so
// appending a junk value can neither switch a Deny off nor switch an Allow
// on. AWS documents neither case; this is a deliberate choice.
//
// Parse has already rejected policy values that cannot be valid for their
// operator. One can still turn invalid here only through a policy variable,
// whose value comes from the request, and the condition then holds only in
// a Deny statement, by the same rule.
//
// Unknown keys resolve against the caller in the same way. When the
// condition's key is unknown (see Request.Unknown), or one of its policy
// values has a variable naming an unknown key, the condition holds exactly
// in a Deny statement, whatever its operator: IfExists, Null, ForAnyValue
// and ForAllValues included. An absent key would instead make negated
// operators, IfExists, Null with true and ForAllValues hold, which in an
// Allow statement grants and in a Deny statement under a positive operator
// stops denying. This too is this package's choice.
func (c condition) holds(vars bool, rc *requestContext, deny bool) bool {
	if c.unknown(vars, rc) {
		return deny
	}
	vals, present, decided, result := c.precheck(rc)
	if decided {
		return result
	}
	if !present {
		return c.missing()
	}
	match, ok := compileValues(c.op.base, c.values, vars && c.op.base.vars(), rc)
	if !ok {
		return deny
	}
	hits := make([]bool, len(vals))
	for i, v := range vals {
		hit, valid := match(v)
		if !valid {
			hit = c.op.base.negated != deny
		}
		hits[i] = hit
	}
	return c.combine(hits)
}

// unknown reports whether the condition's key is unknown, or a policy
// value has a variable naming an unknown key. Variables count only where
// the operator replaces them.
func (c condition) unknown(vars bool, rc *requestContext) bool {
	if !rc.hasUnknown() {
		return false
	}
	if rc.isUnknown(c.key) {
		return true
	}
	vars = vars && c.op.base.vars()
	for _, v := range c.values {
		if mentionsUnknown(v, vars, rc) {
			return true
		}
	}
	return false
}

// precheck looks up the condition's key and decides the Null operator,
// which does not need the key's values.
func (c condition) precheck(rc *requestContext) (vals []string, present, decided, result bool) {
	vals, present = rc.get(c.key)
	if c.op.base.kind == kindNull {
		return nil, false, true, nullHolds(c.values, present)
	}
	if c.op.set != setNone {
		vals = withoutEmpty(vals)
		present = len(vals) > 0
	}
	return vals, present, false, false
}

// withoutEmpty returns vals without its empty strings: for the set
// operators "" is part of a null dataset, not a value, so ["", "x"] is
// ["x"].
func withoutEmpty(vals []string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// missing is the result of the condition when its key is not present.
func (c condition) missing() bool {
	switch {
	case c.op.ifExists, c.op.set == setForAll:
		return true
	case c.op.set == setForAny:
		return false
	default:
		return c.op.base.negated
	}
}

// combine folds whether each request value matched any policy value into
// the condition's result.
//
// Without a set operator a key's request values are treated as one set
// that matches when any value matches; the IAM User Guide requires a set
// operator for a multivalued key and does not define the result without
// one. ForAnyValue holds when at least one request value passes and
// ForAllValues when every one does, where a value passes a negated
// operator when it matches no policy value: "ForAllValues:StringNotEquals
// ... None of the values of the context key in the request can match any
// of the context key values in your policy" and "ForAnyValue:StringNotEquals
// ... At least one context key value in the request must NOT match any of
// values in the context key in your policy." (operators page, "Multivalued
// string condition operators").
func (c condition) combine(hits []bool) bool {
	neg := c.op.base.negated
	switch c.op.set {
	case setForAll:
		return !anyBool(hits, neg)
	case setForAny:
		return anyBool(hits, !neg)
	default:
		return anyBool(hits, true) != neg
	}
}

// anyBool reports whether any of bs equals want.
func anyBool(bs []bool, want bool) bool {
	for _, b := range bs {
		if b == want {
			return true
		}
	}
	return false
}

// nullHolds evaluates the Null operator: "use either true (the key doesn't
// exist — it is null) or false (the key exists and its value is not null)"
// (operators page, "Condition operator to check existence of condition
// keys"). Values other than true and false match nothing.
func nullHolds(values []string, present bool) bool {
	for _, v := range values {
		switch strings.ToLower(v) {
		case "true":
			if !present {
				return true
			}
		case "false":
			if present {
				return true
			}
		}
	}
	return false
}
