package policy

import (
	"errors"
	"testing"
)

// Operator semantics beyond the documented tables: each row follows from
// the operator definitions cited in condition.go and values.go.
var operatorCases = []condCase{
	// IfExists with the key present behaves as the base operator.
	{"IfExists present no match", `{"StringEqualsIfExists":{"k:a":"x"}}`, ctx("k:a", "y"), false},
	{"NotIfExists missing", `{"StringNotEqualsIfExists":{"k:a":"x"}}`, ctx(), true},
	// Negated operators: true for a missing key, NOR across values.
	{"StringNotEquals missing", `{"StringNotEquals":{"k:a":"x"}}`, ctx(), true},
	{"StringNotEquals NOR", `{"StringNotEquals":{"k:a":["x","y"]}}`, ctx("k:a", "y"), false},
	{"StringNotEquals none", `{"StringNotEquals":{"k:a":["x","y"]}}`, ctx("k:a", "z"), true},
	{"NotIpAddress missing", `{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`, ctx(), true},
	{
		"NotIpAddress outside",
		`{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`,
		ctx("aws:SourceIp", "11.0.0.1"),
		true,
	},
	{
		"NotIpAddress inside",
		`{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`,
		ctx("aws:SourceIp", "10.2.3.4"),
		false,
	},
	// Set operators with negated bases.
	{
		"ForAnyValue:StringNotEquals one differs", `{"ForAnyValue:StringNotEquals":{"k:a":["x"]}}`,
		ctx("k:a", "x", "k:a", "y"), true,
	},
	{
		"ForAnyValue:StringNotEquals all equal",
		`{"ForAnyValue:StringNotEquals":{"k:a":["x"]}}`,
		ctx("k:a", "x"),
		false,
	},
	{
		"ForAllValues:StringNotEquals none equal", `{"ForAllValues:StringNotEquals":{"k:a":["x"]}}`,
		ctx("k:a", "y", "k:a", "z"), true,
	},
	{
		"ForAllValues:StringNotEquals one equal", `{"ForAllValues:StringNotEquals":{"k:a":["x"]}}`,
		ctx("k:a", "y", "k:a", "x"), false,
	},
	// "if the context key value resolves to a null dataset, such as an
	// empty string"
	{
		"ForAllValues empty string",
		`{"ForAllValues:StringEquals":{"k:a":"x"}}`,
		ctx("k:a", ""),
		true,
	},
	{"ForAnyValue empty string", `{"ForAnyValue:StringEquals":{"k:a":""}}`, ctx("k:a", ""), false},
	{
		"ForAllValues no values",
		`{"ForAllValues:StringEquals":{"k:a":"x"}}`,
		map[string][]string{"k:a": {}},
		true,
	},
	{
		"ForAnyValueIfExists missing",
		`{"ForAnyValue:StringEqualsIfExists":{"k:a":"x"}}`,
		ctx(),
		true,
	},
	// A multivalued key without a set operator matches when any value
	// matches.
	{"multivalued plain", `{"StringEquals":{"k:a":"x"}}`, ctx("k:a", "y", "k:a", "x"), true},
	// Null.
	{"Null true absent", `{"Null":{"k:a":"true"}}`, ctx(), true},
	{"Null true present", `{"Null":{"k:a":"true"}}`, ctx("k:a", "v"), false},
	{"Null no values", `{"Null":{"k:a":"true"}}`, map[string][]string{"k:a": nil}, true},
	{"Null JSON bool", `{"Null":{"k:a":false}}`, ctx("k:a", "v"), true},
	// Numeric.
	{"Numeric decimal", `{"NumericGreaterThan":{"k:n":"1.5"}}`, ctx("k:n", "1.75"), true},
	{"Numeric JSON number", `{"NumericEquals":{"k:n":10}}`, ctx("k:n", "10.0"), true},
	{"Numeric exponent", `{"NumericEquals":{"k:n":"1e2"}}`, ctx("k:n", "100"), true},
	{"Numeric not a number", `{"NumericLessThan":{"k:n":"10"}}`, ctx("k:n", "abc"), false},
	{
		"NumericNotEquals not a number",
		`{"NumericNotEquals":{"k:n":"10"}}`,
		ctx("k:n", "abc"),
		false, // an invalid value never helps an Allow
	},
	{"Numeric hex rejected", `{"NumericEquals":{"k:n":"16"}}`, ctx("k:n", "0x10"), false},
	// Date.
	{
		"Date before", `{"DateLessThan":{"aws:CurrentTime":"2026-12-01T00:00:00Z"}}`,
		ctx("aws:CurrentTime", "2026-11-13T08:00:00Z"), true,
	},
	{
		"Date after", `{"DateLessThan":{"aws:CurrentTime":"2026-12-01T00:00:00Z"}}`,
		ctx("aws:CurrentTime", "2026-12-01T00:00:01Z"), false,
	},
	{
		"Date offset", `{"DateEquals":{"aws:CurrentTime":"2026-11-13T10:00:00+02:00"}}`,
		ctx("aws:CurrentTime", "2026-11-13T08:00:00Z"), true,
	},
	{
		"Date fraction", `{"DateGreaterThan":{"aws:CurrentTime":"2026-11-13T08:00:00Z"}}`,
		ctx("aws:CurrentTime", "2026-11-13T08:00:00.5Z"), true,
	},
	{
		"Date day", `{"DateGreaterThanEquals":{"aws:CurrentTime":"2026-11-13"}}`,
		ctx("aws:CurrentTime", "2026-11-13T00:00:00Z"), true,
	},
	{
		"Date epoch policy",
		`{"DateLessThan":{"aws:EpochTime":"1700000000"}}`,
		ctx("aws:EpochTime", "1699999999"),
		true,
	},
	{
		"Date epoch vs iso",
		`{"DateEquals":{"aws:CurrentTime":"1970-01-01T00:01:00Z"}}`,
		ctx("aws:CurrentTime", "60"),
		true,
	},
	{
		"Date invalid",
		`{"DateNotEquals":{"aws:CurrentTime":"2026-11-13T08:00:00Z"}}`,
		ctx("aws:CurrentTime", "soon"),
		false,
	},
	// Bool.
	{
		"Bool JSON true",
		`{"Bool":{"aws:SecureTransport":true}}`,
		ctx("aws:SecureTransport", "true"),
		true,
	},
	{
		"Bool case",
		`{"Bool":{"aws:SecureTransport":"True"}}`,
		ctx("aws:SecureTransport", "TRUE"),
		true,
	},
	{
		"Bool invalid request",
		`{"Bool":{"aws:SecureTransport":"true"}}`,
		ctx("aws:SecureTransport", "yes"),
		false,
	},
	// IP addresses.
	{
		"IP v6 prefix", `{"IpAddress":{"aws:SourceIp":"2001:DB8:1234:5678::/64"}}`,
		ctx("aws:SourceIp", "2001:db8:1234:5678::9"), true,
	},
	{
		"IP v6 outside", `{"IpAddress":{"aws:SourceIp":"2001:DB8:1234:5678::/64"}}`,
		ctx("aws:SourceIp", "2001:db8:1234:5679::9"), false,
	},
	{
		"IP default /32",
		`{"IpAddress":{"aws:SourceIp":"203.0.113.5"}}`,
		ctx("aws:SourceIp", "203.0.113.5"),
		true,
	},
	{
		"IP default /32 other",
		`{"IpAddress":{"aws:SourceIp":"203.0.113.5"}}`,
		ctx("aws:SourceIp", "203.0.113.6"),
		false,
	},
	{
		"IP v4 mapped",
		`{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`,
		ctx("aws:SourceIp", "::ffff:203.0.113.9"),
		true,
	},
	{
		"IP mixed list",
		`{"IpAddress":{"aws:SourceIp":["203.0.113.0/24","2001:DB8:1234:5678::/64"]}}`,
		ctx("aws:SourceIp", "2001:db8:1234:5678::1"),
		true,
	},
	{
		"IP invalid request",
		`{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`,
		ctx("aws:SourceIp", "nope"),
		false,
	},
	// ARN operators check each field separately.
	{
		"ArnLike star stays in field",
		`{"ArnLike":{"aws:SourceArn":"arn:aws:sns:*:123456789012:t"}}`,
		ctx("aws:SourceArn", "arn:aws:sns:us-east-1:x:123456789012:t"),
		false,
	},
	{
		"ArnLike resource colons", `{"ArnLike":{"aws:SourceArn":"arn:aws:lambda:*:*:function:*"}}`,
		ctx("aws:SourceArn", "arn:aws:lambda:us-east-1:123456789012:function:f:live"), true,
	},
	{
		"ArnLike case sensitive", `{"ArnLike":{"aws:SourceArn":"arn:aws:sns:*:*:Topic"}}`,
		ctx("aws:SourceArn", "arn:aws:sns:us-east-1:1:topic"), false,
	},
	{
		"ArnNotLike not an arn",
		`{"ArnNotLike":{"aws:SourceArn":"arn:aws:sns:*:*:t"}}`,
		ctx("aws:SourceArn", "t"),
		false,
	},
	{
		"ArnEquals wildcard",
		`{"ArnEquals":{"aws:SourceArn":"arn:aws:s3:::b-?"}}`,
		ctx("aws:SourceArn", "arn:aws:s3:::b-1"),
		true,
	},
	// A Bool or ARN value holding a variable is checked per request: a
	// value that is not a boolean or an ARN makes the condition false.
	{
		"Bool variable not a boolean",
		`{"Bool":{"k:b":"${k:v}"}}`,
		ctx("k:b", "true", "k:v", "maybe"),
		false,
	},
	{"Bool variable", `{"Bool":{"k:b":"${k:v}"}}`, ctx("k:b", "true", "k:v", "TRUE"), true},
	{
		"ArnNotLike variable not an arn", `{"ArnNotLike":{"k:arn":"${k:v}"}}`,
		ctx("k:arn", "arn:aws:s3:::b", "k:v", "b"), false,
	},
}

var variableConditionCases = []condCase{
	{
		"variable in StringEquals", `{"StringEquals":{"k:owner":"${aws:username}"}}`,
		ctx("k:owner", "alice"), true,
	},
	{
		"variable value is literal in StringLike", `{"StringLike":{"k:a":"${k:pat}"}}`,
		ctx("k:a", "abc", "k:pat", "a*"), false,
	},
	{
		"variable literal star matches itself", `{"StringLike":{"k:a":"${k:pat}"}}`,
		ctx("k:a", "a*", "k:pat", "a*"), true,
	},
	{"escape star is literal", `{"StringLike":{"k:a":"a${*}"}}`, ctx("k:a", "ab"), false},
	{"escape star matches star", `{"StringLike":{"k:a":"a${*}"}}`, ctx("k:a", "a*"), true},
	{"escape question and dollar", `{"StringEquals":{"k:a":"${?}${$}"}}`, ctx("k:a", "?$"), true},
	{
		"multivalued key is not a variable", `{"StringEquals":{"k:a":"${k:list}"}}`,
		ctx("k:a", "x", "k:list", "x", "k:list", "y"), false,
	},
	{"variable name case", `{"StringEquals":{"k:a":"${AWS:USERNAME}"}}`, ctx("k:a", "alice"), true},
	{
		"unclosed variable is literal",
		`{"StringEquals":{"k:a":"${aws:username"}}`,
		ctx("k:a", "${aws:username"),
		true,
	},
	{
		"variable in ArnEquals", `{"ArnEquals":{"k:arn":"${aws:PrincipalArn}"}}`,
		ctx("k:arn", "arn:aws:iam::111122223333:user/alice"), true,
	},
	{"principal account", `{"StringEquals":{"aws:PrincipalAccount":"111122223333"}}`, ctx(), true},
	{
		"context wins over principal",
		`{"StringEquals":{"aws:username":"alice"}}`,
		ctx("aws:username", "bob"),
		false,
	},
}

func TestOperators(t *testing.T) {
	t.Run("operators", func(t *testing.T) { runCondCases(t, operatorCases) })
	t.Run("variables", func(t *testing.T) { runCondCases(t, variableConditionCases) })
}

// A Deny statement with an unknown operator is refused at Parse, so it
// cannot silently deny nothing.
func TestUnknownOperatorDenyRejected(t *testing.T) {
	_, err := Parse([]byte(condPolicy("Deny", `{"StringEqualz":{"k:a":"x"}}`)))
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Message != "Condition operator StringEqualz is not valid." {
		t.Errorf("Parse = %v, want the unknown operator refused", err)
	}
}

// "If you are using an "Effect": "Deny" element with a negated condition
// operator like StringNotEqualsIfExists, the request is still denied even
// if the condition key is not present." (operators page, IfExists).
func TestDenyNegatedIfExistsMissingKey(t *testing.T) {
	deny := mustParse(
		t,
		condPolicy("Deny", `{"StringNotEqualsIfExists":{"aws:PrincipalServiceName":"x"}}`),
	)
	if got := Evaluate(
		anyRequest(ctx()),
		mustParse(t, allowAll),
		deny,
	); got.Decision != ExplicitDeny {
		t.Errorf("Evaluate = %+v, want ExplicitDeny", got)
	}
}

// junkCases: a value invalid for the operator is a non-match for that value
// alone and never switches a condition off.
var junkCases = []condCase{
	{
		"plain junk then match",
		`{"NumericGreaterThan":{"k:n":"10"}}`,
		ctx("k:n", "junk", "k:n", "11"),
		true,
	},
	{"plain only junk", `{"NumericGreaterThan":{"k:n":"10"}}`, ctx("k:n", "junk"), false},
	{
		"negated junk and match",
		`{"NumericNotEquals":{"k:n":"10"}}`,
		ctx("k:n", "junk", "k:n", "10"),
		false,
	},
	{
		"ForAnyValue junk then match",
		`{"ForAnyValue:NumericEquals":{"k:n":"1"}}`,
		ctx("k:n", "junk", "k:n", "1"),
		true,
	},
	{
		"ForAnyValue only junk",
		`{"ForAnyValue:NumericEquals":{"k:n":"1"}}`,
		ctx("k:n", "junk"),
		false,
	},
	{
		"ForAnyValue negated only junk",
		`{"ForAnyValue:NumericNotEquals":{"k:n":"1"}}`,
		ctx("k:n", "junk"),
		false,
	},
	{
		"ForAllValues junk",
		`{"ForAllValues:NumericEquals":{"k:n":"1"}}`,
		ctx("k:n", "1", "k:n", "junk"),
		false,
	},
	{
		"ForAllValues negated junk",
		`{"ForAllValues:NumericNotEquals":{"k:n":"1"}}`,
		ctx("k:n", "2", "k:n", "junk"),
		false,
	},
	{
		"ForAllValues valid",
		`{"ForAllValues:NumericNotEquals":{"k:n":"1"}}`,
		ctx("k:n", "2", "k:n", "3"),
		true,
	},
}

func TestJunkRequestValues(t *testing.T) { runCondCases(t, junkCases) }

// junkFamilies is one condition per operator family that can see an
// invalid request value, with that value. String operators have none:
// every string is valid for them.
var junkFamilies = []struct{ name, condition, junk string }{
	{"NumericEquals", `{"NumericEquals":{"k:v":"10"}}`, "ten"},
	{"NumericNotEquals", `{"NumericNotEquals":{"k:v":"10"}}`, "ten"},
	{"NumericGreaterThan", `{"NumericGreaterThan":{"k:v":"10"}}`, "ten"},
	{"DateLessThan", `{"DateLessThan":{"k:v":"2026-01-01"}}`, "soon"},
	{"DateNotEquals", `{"DateNotEquals":{"k:v":"2026-01-01"}}`, "never"},
	{"Bool", `{"Bool":{"k:v":"true"}}`, "yes"},
	{"BinaryEquals", `{"BinaryEquals":{"k:v":"QQ=="}}`, "not base64!"},
	{"IpAddress", `{"IpAddress":{"k:v":"10.0.0.0/8"}}`, "nope"},
	{"NotIpAddress", `{"NotIpAddress":{"k:v":"10.0.0.0/8"}}`, "nope"},
	{"ArnLike", `{"ArnLike":{"k:v":"arn:aws:s3:::*"}}`, "bucket"},
	{"ArnNotLike", `{"ArnNotLike":{"k:v":"arn:aws:s3:::*"}}`, "bucket"},
	{"ForAnyValue:NumericEquals", `{"ForAnyValue:NumericEquals":{"k:v":"1"}}`, "x"},
	{"ForAnyValue:NumericNotEquals", `{"ForAnyValue:NumericNotEquals":{"k:v":"1"}}`, "x"},
	{"ForAllValues:NumericEquals", `{"ForAllValues:NumericEquals":{"k:v":"1"}}`, "x"},
	{"ForAllValues:NumericNotEquals", `{"ForAllValues:NumericNotEquals":{"k:v":"1"}}`, "x"},
	{"NumericEqualsIfExists", `{"NumericEqualsIfExists":{"k:v":"1"}}`, "x"},
}

// Malformed request values never grant and always deny: a condition whose
// outcome depends on a junk value never holds in an Allow and always holds
// in a Deny, whatever the operator.
func TestJunkNeverGrantsAlwaysDenies(t *testing.T) {
	allow := mustParse(t, allowAll)
	for _, f := range junkFamilies {
		r := anyRequest(ctx("k:v", f.junk))
		if got := Evaluate(
			r,
			mustParse(t, condPolicy("Allow", f.condition)),
		); got.Decision != ImplicitDeny {
			t.Errorf("%s Allow on junk: %+v, want ImplicitDeny", f.name, got)
		}
		if got := Evaluate(
			r,
			allow,
			mustParse(t, condPolicy("Deny", f.condition)),
		); got.Decision != ExplicitDeny {
			t.Errorf("%s Deny on junk: %+v, want ExplicitDeny", f.name, got)
		}
	}
}

// A junk value appended to a multivalued key cannot switch off a Deny.
func TestJunkValueDoesNotDisableDeny(t *testing.T) {
	allow := mustParse(t, allowAll)
	for _, c := range []struct{ name, condition, valid string }{
		{"NumericGreaterThan over the limit", `{"NumericGreaterThan":{"k:n":"10"}}`, "11"},
		{"NumericGreaterThan under the limit", `{"NumericGreaterThan":{"k:n":"10"}}`, "9"},
		{"StringNotEquals", `{"StringNotEquals":{"k:n":"ok"}}`, "other"},
		{"ForAllValues:NumericEquals", `{"ForAllValues:NumericEquals":{"k:n":"1"}}`, "1"},
		{"ForAnyValue:NumericNotEquals", `{"ForAnyValue:NumericNotEquals":{"k:n":"1"}}`, "1"},
	} {
		deny := mustParse(t, condPolicy("Deny", c.condition))
		r := anyRequest(ctx("k:n", "junk", "k:n", c.valid))
		if got := Evaluate(r, allow, deny); got.Decision != ExplicitDeny {
			t.Errorf("%s: Evaluate = %+v, want ExplicitDeny", c.name, got)
		}
	}
}
