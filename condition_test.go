package policy

import "testing"

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
		false,
	},
	{"Numeric hex rejected", `{"NumericEquals":{"k:n":"16"}}`, ctx("k:n", "0x10"), false},
	{"Numeric bad policy value", `{"NumericNotEquals":{"k:n":"ten"}}`, ctx("k:n", "1"), false},
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
	// Unknown operators never hold.
	{"unknown operator", `{"StringEqualz":{"k:a":"x"}}`, ctx("k:a", "x"), false},
	{"unknown negated-looking operator", `{"StringNotEqualz":{"k:a":"x"}}`, ctx(), false},
	{"Null IfExists", `{"NullIfExists":{"k:a":"true"}}`, ctx(), false},
	{"set operator on Null", `{"ForAnyValue:Null":{"k:a":"true"}}`, ctx(), false},
	{"operator case", `{"stringequals":{"k:a":"x"}}`, ctx("k:a", "x"), false},
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
		"variables not in Numeric",
		`{"NumericEquals":{"k:n":"${k:m}"}}`,
		ctx("k:n", "1", "k:m", "1"),
		false,
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

// An unknown operator makes a Deny statement not apply either, so it
// denies nothing.
func TestUnknownOperatorDenyDoesNotApply(t *testing.T) {
	allow := mustParse(t, allowAll)
	deny := mustParse(t, condPolicy("Deny", `{"StringEqualz":{"k:a":"x"}}`))
	if got := Evaluate(anyRequest(ctx("k:a", "x")), allow, deny); got.Decision != Allow {
		t.Errorf("Evaluate = %+v, want Allow", got)
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
