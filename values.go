package policy

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// matcher reports whether a request value matches any of a condition's
// policy values, and whether the request value is valid for the operator.
type matcher func(v string) (match, valid bool)

// compileValues compiles a condition's policy values for its operator. ok
// is false when a policy value is not valid for the operator.
//
// A policy value whose variable has no value is dropped: "When you use a
// variable with no value in the condition element of an IAM policy,
// condition operators like StringEquals or StringLike do not match, and the
// policy statement does not take effect. Inverted condition operators like
// StringNotEquals or StringNotLike do match against a null value"
// ("IAM policy elements: Variables and tags", policy variables with no
// value, https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html).
func compileValues(b baseOp, raw []string, vars bool, rc *requestContext) (matcher, bool) {
	switch b.kind {
	case kindString, kindStringFold:
		return stringMatcher(raw, vars, rc, b.kind == kindStringFold), true
	case kindStringLike:
		return likeMatcher(raw, vars, rc), true
	case kindARN:
		return arnMatcher(raw, vars, rc)
	case kindBool:
		return boolMatcher(raw, vars, rc)
	case kindNumeric:
		return orderedMatcher(raw, parseNumber, b.order)
	case kindDate:
		return orderedMatcher(raw, parseDate, b.order)
	case kindBinary:
		return binaryMatcher(raw)
	case kindIP:
		return ipMatcher(raw)
	default:
		return nil, false
	}
}

// stringMatcher implements StringEquals ("Exact matching, case sensitive")
// and, with fold, StringEqualsIgnoreCase ("Exact matching, ignoring case").
func stringMatcher(raw []string, vars bool, rc *requestContext, fold bool) matcher {
	want := make([]string, 0, len(raw))
	for _, r := range raw {
		if s, ok := expandString(r, vars, rc); ok {
			want = append(want, s)
		}
	}
	return func(v string) (bool, bool) {
		for _, w := range want {
			if v == w || fold && strings.EqualFold(v, w) {
				return true, true
			}
		}
		return false, true
	}
}

// likeMatcher implements StringLike: "Case-sensitive matching. The values
// can include multi-character match wildcards (*) and single-character
// match wildcards (?) anywhere in the string."
func likeMatcher(raw []string, vars bool, rc *requestContext) matcher {
	pats := make([]pattern, 0, len(raw))
	for _, r := range raw {
		if p, ok := expand(nil, r, vars, rc); ok {
			pats = append(pats, p)
		}
	}
	return func(v string) (bool, bool) {
		for _, p := range pats {
			if p.match(v, false) {
				return true, true
			}
		}
		return false, true
	}
}

// arnMatcher implements ArnEquals and ArnLike, field by field (see
// arnFields). A request value that is not an ARN of six fields is invalid.
func arnMatcher(raw []string, vars bool, rc *requestContext) (matcher, bool) {
	fields := make([][6]pattern, 0, len(raw))
	for _, r := range raw {
		p, ok := expand(nil, r, vars, rc)
		if !ok {
			continue
		}
		f, ok := arnFields(p)
		if !ok {
			return nil, false
		}
		fields = append(fields, f)
	}
	return func(v string) (bool, bool) {
		if strings.Count(v, ":") < 5 {
			return false, false
		}
		for _, f := range fields {
			if matchARNFields(f, v) {
				return true, true
			}
		}
		return false, true
	}, true
}

// boolMatcher implements Bool. Values are "true" or "false" in any case;
// "Quotation marks are optional for numeric and Boolean values" ("Grammar
// of the IAM JSON policy language"), so a JSON true or false arrives here
// as the same text.
func boolMatcher(raw []string, vars bool, rc *requestContext) (matcher, bool) {
	want := make([]bool, 0, len(raw))
	for _, r := range raw {
		s, ok := expandString(r, vars, rc)
		if !ok {
			continue
		}
		b, ok := parseBool(s)
		if !ok {
			return nil, false
		}
		want = append(want, b)
	}
	return func(v string) (bool, bool) {
		b, ok := parseBool(v)
		if !ok {
			return false, false
		}
		for _, w := range want {
			if b == w {
				return true, true
			}
		}
		return false, true
	}, true
}

func parseBool(s string) (bool, bool) {
	switch strings.ToLower(s) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

// ordered is a value that Numeric and Date operators compare.
type ordered interface{ float64 | int64 }

// orderedMatcher implements the Numeric and Date operators: the request's
// value is compared with each policy value, as in NumericLessThan's "Less
// than" matching or DateLessThan's "Matching before a specific date and
// time".
func orderedMatcher[T ordered](
	raw []string,
	parse func(string) (T, bool),
	o order,
) (matcher, bool) {
	want := make([]T, 0, len(raw))
	for _, r := range raw {
		w, ok := parse(r)
		if !ok {
			return nil, false
		}
		want = append(want, w)
	}
	return func(v string) (bool, bool) {
		got, ok := parse(v)
		if !ok {
			return false, false
		}
		for _, w := range want {
			if compare(got, w, o) {
				return true, true
			}
		}
		return false, true
	}, true
}

func compare[T ordered](got, want T, o order) bool {
	switch o {
	case orderLt:
		return got < want
	case orderLe:
		return got <= want
	case orderGt:
		return got > want
	case orderGe:
		return got >= want
	default:
		return got == want
	}
}

// parseNumber parses "an integer or decimal value" (operators page,
// "Numeric condition operators"): an optional sign, digits with an optional
// fraction, and an optional exponent. Hexadecimal, Inf and NaN are not
// numbers here, and values compare as float64.
func parseNumber(s string) (float64, bool) {
	if !isDecimal(s) {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

func isDecimal(s string) bool {
	mant, exp, hasExp := strings.Cut(strings.ToLower(trimSign(s)), "e")
	whole, frac, _ := strings.Cut(mant, ".")
	if whole == "" && frac == "" || !digits(whole) || !digits(frac) {
		return false
	}
	exp = trimSign(exp)
	return !hasExp || exp != "" && digits(exp)
}

func trimSign(s string) string {
	if s != "" && (s[0] == '+' || s[0] == '-') {
		return s[1:]
	}
	return s
}

func digits(s string) bool {
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// dateLayouts are the W3C profile of ISO 8601 ("Date and Time Formats",
// https://www.w3.org/TR/NOTE-datetime), which the operators page names:
// "You must specify date/time values with one of the W3C implementations of
// the ISO 8601 date formats or in epoch (UNIX) time." time.Parse accepts a
// fractional second after the seconds field, the W3C "s" form. The
// year-only form, YYYY, is all digits and so is read as epoch seconds.
var dateLayouts = []string{
	"2006-01",
	"2006-01-02",
	"2006-01-02T15:04Z07:00",
	"2006-01-02T15:04:05Z07:00",
}

// parseDate parses a date as Unix nanoseconds. A value of only digits is
// epoch seconds.
func parseDate(s string) (int64, bool) {
	if s != "" && digits(s) {
		sec, err := strconv.ParseInt(s, 10, 64)
		if err != nil || sec > maxEpoch {
			return 0, false
		}
		return sec * int64(time.Second), true
	}
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UnixNano(), true
		}
	}
	return 0, false
}

// maxEpoch is the largest epoch second whose nanoseconds fit in an int64.
const maxEpoch = (1<<63 - 1) / int64(time.Second)

// binaryMatcher implements BinaryEquals: "It compares the value of the
// specified key byte for byte against a base-64 encoded representation of
// the binary value in the policy." The request value is base-64 too, as in
// the page's example table; both are decoded and compared.
func binaryMatcher(raw []string) (matcher, bool) {
	want := make([][]byte, 0, len(raw))
	for _, r := range raw {
		b, err := base64.StdEncoding.DecodeString(r)
		if err != nil {
			return nil, false
		}
		want = append(want, b)
	}
	return func(v string) (bool, bool) {
		got, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return false, false
		}
		for _, w := range want {
			if bytes.Equal(got, w) {
				return true, true
			}
		}
		return false, true
	}, true
}

// ipMatcher implements IpAddress: "The value must be in the standard CIDR
// format (for example, 203.0.113.0/24 or 2001:DB8:1234:5678::/64). If you
// specify an IP address without the associated routing prefix, IAM uses
// the default prefix value of /32." An IPv6 address without a prefix is a
// single address, /128.
func ipMatcher(raw []string) (matcher, bool) {
	want := make([]netip.Prefix, 0, len(raw))
	for _, r := range raw {
		p, ok := parsePrefix(r)
		if !ok {
			return nil, false
		}
		want = append(want, p)
	}
	return func(v string) (bool, bool) {
		a, err := netip.ParseAddr(v)
		if err != nil || a.Zone() != "" {
			return false, false
		}
		a = a.Unmap()
		for _, p := range want {
			if p.Contains(a) {
				return true, true
			}
		}
		return false, true
	}, true
}

func parsePrefix(s string) (netip.Prefix, bool) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, false
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96), true
	}
	return p, true
}

// checkConditionValue reports whether a policy value can be valid for the
// operator: a number for Numeric, a date for Date, an address or CIDR for
// IpAddress, base64 for BinaryEquals, true or false for Bool and Null, and
// an ARN of six fields for the ARN operators. A Bool or ARN value holding a
// policy variable (with vars) is accepted, since its value is known only
// per request. String values are always valid.
func checkConditionValue(b baseOp, v string, vars bool) bool {
	if (b.kind == kindBool || b.kind == kindARN) && vars && strings.Contains(v, "${") {
		return true
	}
	check, ok := valueCheckers[b.kind]
	return !ok || check(v)
}

// valueCheckers validates policy values by operator family; families
// without one accept any string.
var valueCheckers = map[valueKind]func(string) bool{
	kindNumeric: func(v string) bool { _, ok := parseNumber(v); return ok },
	kindDate:    func(v string) bool { _, ok := parseDate(v); return ok },
	kindIP:      func(v string) bool { _, ok := parsePrefix(v); return ok },
	kindBinary: func(v string) bool {
		_, err := base64.StdEncoding.DecodeString(v)
		return err == nil
	},
	kindNull: func(v string) bool { _, ok := parseBool(v); return ok },
	kindBool: func(v string) bool { _, ok := parseBool(v); return ok },
	kindARN:  func(v string) bool { return strings.Count(v, ":") >= 5 },
}
