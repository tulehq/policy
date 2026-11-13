package policy

import "testing"

// The rows in this file are the condition tables of the IAM User Guide,
// each with the outcome the guide states for it. Page names:
//
//   - operators: "IAM JSON policy elements: Condition operators",
//     https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
//   - multivalued: "Single-valued vs. multivalued context keys",
//     https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html
//   - multiple: "Conditions with multiple context keys or values",
//     https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-logic-multiple-context-keys-or-values.html
//   - condition: "IAM JSON policy elements: Condition",
//     https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html

const (
	condJobCategory = `{"StringEquals":{"aws:PrincipalTag/job-category":"iamuser-admin"}}`
	condTagsAny     = `{"StringEqualsIgnoreCase":{"aws:RequestTag/environment":["preprod","storage"]},` +
		`"ForAnyValue:StringEquals":{"aws:TagKeys":"environment"}}`
	condSecureTransport = `{"Bool":{"aws:SecureTransport":"false"}}`
	condBinary          = `{"BinaryEquals":{"key":"QmluYXJ5VmFsdWVJbkJhc2U2NA=="}}`
	condSourceIP        = `{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`
	condSourceArn       = `{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:us-west-2:123456789012:TOPIC-ID"}}`
	condLogArns         = `{"ForAllValues:ArnLike":{"logs:LogGeneratingResourceArns":[` +
		`"arn:aws::cloudfront:123456789012:distribution/*",` +
		`"arn:aws::cloudfront:123456789012:distribution/support*"]}}`
	condInstanceType = `{"StringLikeIfExists":{"ec2:InstanceType":["t1.*","t2.*","m3.*"]}}`
	condTagKeysAll   = `{"ForAllValues:StringEquals":{"aws:TagKeys":["environment","cost-center"]},` +
		`"Null":{"aws:TagKeys":"false"}}`
	condTagKeysAny = `{"ForAnyValue:StringEquals":{"aws:TagKeys":["environment","cost-center"]}}`
	condPrincipal  = `{"StringEquals":{"aws:PrincipalTag/department":["finance","hr","legal"],` +
		`"aws:PrincipalTag/role":["audit","security"]},` +
		`"ArnLike":{"aws:PrincipalArn":["arn:aws:iam::222222222222:user/Ana","arn:aws:iam::222222222222:user/Mary"]}}`
	condPrincipalNot = `{"StringEquals":{"aws:PrincipalTag/department":["finance","hr","legal"],` +
		`"aws:PrincipalTag/role":["audit","security"]},` +
		`"ArnNotLike":{"aws:PrincipalArn":["arn:aws:iam::222222222222:user/Ana","arn:aws:iam::222222222222:user/Mary"]}}`
)

const (
	ana   = "arn:aws:iam::222222222222:user/Ana"
	mary  = "arn:aws:iam::222222222222:user/Mary"
	nikki = "arn:aws:iam::222222222222:user/Nikki"
)

var operatorPageCases = []condCase{
	// operators, "Example string condition operator".
	{
		"job-category iamuser-admin",
		condJobCategory,
		ctx("aws:PrincipalTag/job-category", "iamuser-admin"),
		true,
	},
	{
		"job-category dev-ops",
		condJobCategory,
		ctx("aws:PrincipalTag/job-category", "dev-ops"),
		false,
	},
	{"job-category missing", condJobCategory, ctx(), false},

	// operators, "Example using ForAnyValue with a string condition operator".
	{
		"tags environment preprod", condTagsAny,
		ctx("aws:TagKeys", "environment", "aws:RequestTag/environment", "preprod"), true,
	},
	{
		"tags environment costcenter PreProd",
		condTagsAny,
		ctx(
			"aws:TagKeys",
			"environment",
			"aws:TagKeys",
			"costcenter",
			"aws:RequestTag/environment",
			"PreProd",
		),
		true,
	},
	{
		"tags Environment preprod", condTagsAny,
		ctx("aws:TagKeys", "Environment", "aws:RequestTag/Environment", "preprod"), false,
	},
	{
		"tags costcenter preprod", condTagsAny,
		ctx("aws:TagKeys", "costcenter", "aws:RequestTag/environment", "preprod"), false,
	},
	{"tags no TagKeys", condTagsAny, ctx("aws:RequestTag/environment", "storage"), false},
	{"tags no RequestTag", condTagsAny, ctx("aws:TagKeys", "environment"), false},
	{"tags none", condTagsAny, ctx(), false},

	// operators, "Example boolean condition operator".
	{"SecureTransport false", condSecureTransport, ctx("aws:SecureTransport", "false"), true},
	{"SecureTransport true", condSecureTransport, ctx("aws:SecureTransport", "true"), false},
	{"SecureTransport missing", condSecureTransport, ctx(), false},

	// operators, "Binary condition operators".
	{"binary equal", condBinary, ctx("key", "QmluYXJ5VmFsdWVJbkJhc2U2NA=="), true},
	{"binary other", condBinary, ctx("key", "ASIAIOSFODNN7EXAMPLE"), false},
	{"binary missing", condBinary, ctx(), false},

	// operators, "Example IP address condition operator".
	{"ip inside", condSourceIP, ctx("aws:SourceIp", "203.0.113.1"), true},
	{"ip outside", condSourceIP, ctx("aws:SourceIp", "198.51.100.1"), false},

	// operators, "Example ARN condition operator".
	{
		"arn equal",
		condSourceArn,
		ctx("aws:SourceArn", "arn:aws:sns:us-west-2:123456789012:TOPIC-ID"),
		true,
	},
	{
		"arn other account",
		condSourceArn,
		ctx("aws:SourceArn", "arn:aws:sns:us-west-2:777788889999:TOPIC-ID"),
		false,
	},
	{"arn missing", condSourceArn, ctx(), false},

	// operators, "Example using ForAllValues with an ARN condition operator".
	{
		"log arns costcenter",
		condLogArns,
		ctx(
			"logs:LogGeneratingResourceArns",
			"arn:aws::cloudfront:123456789012:distribution/costcenter",
		),
		true,
	},
	{
		"log arns costcenter support2025",
		condLogArns,
		ctx(
			"logs:LogGeneratingResourceArns",
			"arn:aws::cloudfront:123456789012:distribution/costcenter",
			"logs:LogGeneratingResourceArns",
			"arn:aws::cloudfront:123456789012:distribution/support2025",
		),
		true,
	},
	{
		"log arns costcenter admin",
		condLogArns,
		ctx(
			"logs:LogGeneratingResourceArns",
			"arn:aws::cloudfront:123456789012:distribution/costcenter",
			"logs:LogGeneratingResourceArns",
			"arn:aws::cloudfront:123456789012:distribution/admin",
		),
		true,
	},
	{
		"log arns other account",
		condLogArns,
		ctx(
			"logs:LogGeneratingResourceArns",
			"arn:aws::cloudfront:777788889999:distribution/costcenter",
		),
		false,
	},
	{"log arns missing", condLogArns, ctx(), true},

	// operators, "Example using IfExists".
	{"instance type t1.micro", condInstanceType, ctx("ec2:InstanceType", "t1.micro"), true},
	{"instance type m2.micro", condInstanceType, ctx("ec2:InstanceType", "m2.micro"), false},
	{"instance type missing", condInstanceType, ctx(), true},
	// The same page's THISPOLICYDOESNOTWORK statement: without IfExists,
	// "These additional resources do not have the ec2:InstanceType
	// condition key, so the StringLike check fails".
	{
		"instance type missing without IfExists",
		`{"StringLike":{"ec2:InstanceType":["t1.*","t2.*","m3.*"]}}`, ctx(), false,
	},
}

var multivaluedPageCases = []condCase{
	// multivalued, "Example ForAllValues set operator".
	{"all environment", condTagKeysAll, ctx("aws:TagKeys", "environment"), true},
	{"all cost-center", condTagKeysAll, ctx("aws:TagKeys", "cost-center"), true},
	{
		"all both",
		condTagKeysAll,
		ctx("aws:TagKeys", "environment", "aws:TagKeys", "cost-center"),
		true,
	},
	{
		"all environment dept",
		condTagKeysAll,
		ctx("aws:TagKeys", "environment", "aws:TagKeys", "dept"),
		false,
	},
	{"all missing", condTagKeysAll, ctx(), false},

	// multivalued, "Example ForAnyValue set operator".
	{"any environment", condTagKeysAny, ctx("aws:TagKeys", "environment"), true},
	{"any cost-center", condTagKeysAny, ctx("aws:TagKeys", "cost-center"), true},
	{
		"any both",
		condTagKeysAny,
		ctx("aws:TagKeys", "environment", "aws:TagKeys", "cost-center"),
		true,
	},
	{
		"any environment dept",
		condTagKeysAny,
		ctx("aws:TagKeys", "environment", "aws:TagKeys", "dept"),
		true,
	},
	{"any dept", condTagKeysAny, ctx("aws:TagKeys", "dept"), false},
	{"any missing", condTagKeysAny, ctx(), false},
}

var multipleKeysPageCases = []condCase{
	// multiple, "Evaluation logic for multiple context keys or values".
	{"legal audit Mary", condPrincipal, ctx("aws:PrincipalTag/department", "legal",
		"aws:PrincipalTag/role", "audit", "aws:PrincipalArn", mary), true},
	{"hr audit Nikki", condPrincipal, ctx("aws:PrincipalTag/department", "hr",
		"aws:PrincipalTag/role", "audit", "aws:PrincipalArn", nikki), false},
	{"hr payroll Mary", condPrincipal, ctx("aws:PrincipalTag/department", "hr",
		"aws:PrincipalTag/role", "payroll", "aws:PrincipalArn", mary), false},
	{"hr no role Mary", condPrincipal, ctx("aws:PrincipalTag/department", "hr",
		"aws:PrincipalArn", mary), false},
	{"no tags Mary", condPrincipal, ctx("aws:PrincipalArn", mary), false},

	// multiple, "Evaluation logic for negated matching condition operators".
	{"not: legal audit Nikki", condPrincipalNot, ctx("aws:PrincipalTag/department", "legal",
		"aws:PrincipalTag/role", "audit", "aws:PrincipalArn", nikki), true},
	{"not: hr audit Mary", condPrincipalNot, ctx("aws:PrincipalTag/department", "hr",
		"aws:PrincipalTag/role", "audit", "aws:PrincipalArn", mary), false},
	{"not: hr payroll Nikki", condPrincipalNot, ctx("aws:PrincipalTag/department", "hr",
		"aws:PrincipalTag/role", "payroll", "aws:PrincipalArn", nikki), false},
	{"not: hr no role Nikki", condPrincipalNot, ctx("aws:PrincipalTag/department", "hr",
		"aws:PrincipalArn", nikki), false},
	{"not: no tags Nikki", condPrincipalNot, ctx("aws:PrincipalArn", nikki), false},
}

var conditionPageCases = []condCase{
	// condition: "only requests made by john match. Users named John are
	// denied access", and StringEqualsIgnoreCase matches "john or John".
	{
		"username john",
		`{"StringEquals":{"aws:username":"john"}}`,
		ctx("aws:username", "john"),
		true,
	},
	{
		"username John",
		`{"StringEquals":{"aws:username":"john"}}`,
		ctx("aws:username", "John"),
		false,
	},
	{
		"ignore case John",
		`{"StringEqualsIgnoreCase":{"aws:username":"john"}}`,
		ctx("aws:username", "John"),
		true,
	},
	// condition: "including the aws:SourceIP context key is equivalent to
	// testing for AWS:SourceIp."
	{
		"key name case",
		`{"IpAddress":{"aws:SourceIP":"203.0.113.0/24"}}`,
		ctx("AWS:SourceIp", "203.0.113.7"),
		true,
	},
	// condition: "the value for aws:MultiFactorAuthAge is 2800, which is
	// less than 3600, so the policy allows this authorization request."
	{
		"mfa age", `{"NumericLessThanEquals":{"aws:MultiFactorAuthAge":"3600"}}`,
		ctx("aws:MultiFactorAuthAge", "2800"), true,
	},
	// operators, numeric: "only the operations that include the max-keys
	// context key with a value of less than or equal to 10 would be
	// allowed."
	{
		"max-keys 10",
		`{"NumericLessThanEquals":{"s3:max-keys":"10"}}`,
		ctx("s3:max-keys", "10"),
		true,
	},
	{
		"max-keys 11",
		`{"NumericLessThanEquals":{"s3:max-keys":"10"}}`,
		ctx("s3:max-keys", "11"),
		false,
	},
	{"max-keys missing", `{"NumericLessThanEquals":{"s3:max-keys":"10"}}`, ctx(), false},
	// operators, date: "The aws:TokenIssueTime key is present in the
	// request context only when the principal uses temporary credentials
	// ... if an IAM user attempts to view or edit an access key, the
	// request is denied."
	{
		"token issue time missing",
		`{"DateGreaterThan":{"aws:TokenIssueTime":"2020-01-01T00:00:01Z"}}`,
		ctx(),
		false,
	},
	// operators, Null: "the user must be using temporary credentials (the
	// key cannot be absent)".
	{
		"null false present", `{"Null":{"aws:TokenIssueTime":"false"}}`,
		ctx("aws:TokenIssueTime", "2026-11-13T08:00:00Z"), true,
	},
	{"null false absent", `{"Null":{"aws:TokenIssueTime":"false"}}`, ctx(), false},
}

func TestDocumentedConditionTables(t *testing.T) {
	t.Run("operators", func(t *testing.T) { runCondCases(t, operatorPageCases) })
	t.Run("multivalued", func(t *testing.T) { runCondCases(t, multivaluedPageCases) })
	t.Run("multiple", func(t *testing.T) { runCondCases(t, multipleKeysPageCases) })
	t.Run("condition", func(t *testing.T) { runCondCases(t, conditionPageCases) })
}
