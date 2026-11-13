package policy

import "testing"

// The cases in this file are the IAM User Guide's policy examples that
// state an outcome. Each names its page.

const carlosPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "AllowS3ListRead", "Effect": "Allow",
     "Action": ["s3:GetBucketLocation", "s3:GetAccountPublicAccessBlock", "s3:ListAccessPoints", "s3:ListAllMyBuckets"],
     "Resource": "arn:aws:s3:::*"},
    {"Sid": "AllowS3Self", "Effect": "Allow", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar/*", "arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar"]},
    {"Sid": "DenyS3Logs", "Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::*log*"}
  ]
}`

const carlos = "arn:aws:iam::123456789012:user/carlossalazar"

// "Policy evaluation for requests within a single account", example
// identity-based and resource-based policy evaluation,
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-basics.html.
func TestEvaluationLogicExample(t *testing.T) {
	p := mustParse(t, carlosPolicy)
	logs := Request{
		Action: "s3:PutObject", Principal: carlos,
		Resource: "arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar-logs/file.txt",
	}
	// "It finds one, because the identity-based policy explicitly denies
	// Carlos access to any S3 buckets used for logging. Carlos is denied
	// access."
	if got, want := Evaluate(
		logs,
		p,
	), (Result{Decision: ExplicitDeny, Policy: 0, Sid: "DenyS3Logs"}); got != want {
		t.Errorf("logs bucket: %+v, want %+v", got, want)
	}
	// "AWS checks for a Deny statement and does not find one. ... AWS
	// allows the request."
	own := logs
	own.Resource = "arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar/file.txt"
	if got, want := Evaluate(
		own,
		p,
	), (Result{Decision: Allow, Policy: 0, Sid: "AllowS3Self"}); got != want {
		t.Errorf("own bucket: %+v, want %+v", got, want)
	}
}

func s3Get(resource string) Request {
	return Request{
		Action:    "s3:GetObject",
		Resource:  resource,
		Principal: "arn:aws:iam::111122223333:user/alice",
	}
}

// "IAM JSON policy elements: Resource", using wildcards in resource ARNs:
// "The wildcards in the ARN apply to all of the following objects in the
// bucket" and "The ARN would not match the following objects".
var resourceWildcardCases = func() []evalCase {
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject",` +
		`"Resource":"arn:aws:s3:::amzn-s3-demo-bucket/*/test/*"}}`
	match := []string{
		"amzn-s3-demo-bucket/1/test/object.jpg",
		"amzn-s3-demo-bucket/1/2/test/object.jpg",
		"amzn-s3-demo-bucket/1/2/test/3/object.jpg",
		"amzn-s3-demo-bucket/1/2/3/test/4/object.jpg",
		"amzn-s3-demo-bucket/1///test///object.jpg",
		"amzn-s3-demo-bucket/1/test/.jpg",
		"amzn-s3-demo-bucket//test/object.jpg",
		"amzn-s3-demo-bucket/1/test/",
	}
	noMatch := []string{
		"amzn-s3-demo-bucket/1-test/object.jpg",
		"amzn-s3-demo-bucket/test/object.jpg",
		"amzn-s3-demo-bucket/1/2/test.jpg",
	}
	cases := make([]evalCase, 0, len(match)+len(noMatch))
	for _, o := range match {
		cases = append(cases, evalCase{o, []string{doc}, s3Get("arn:aws:s3:::" + o), Allow})
	}
	for _, o := range noMatch {
		cases = append(cases, evalCase{o, []string{doc}, s3Get("arn:aws:s3:::" + o), ImplicitDeny})
	}
	return cases
}()

func allowOn(action, resource string) string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"` + action +
		`","Resource":"` + resource + `"}}`
}

// "Identify AWS resources with Amazon Resource Names (ARNs)", using
// wildcards in paths, https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html,
// and the incomplete-ARN note of "Grammar of the IAM JSON policy language".
var arnPageCases = []evalCase{
	{
		"role/* any role",
		[]string{allowOn("iam:GetRole", "arn:aws:iam::123456789012:role/*")},
		req("iam:GetRole", "arn:aws:iam::123456789012:role/admin"), Allow,
	},
	{
		"role/service-* service-role1",
		[]string{allowOn("iam:GetRole", "arn:aws:iam::123456789012:role/service-*")},
		req("iam:GetRole", "arn:aws:iam::123456789012:role/service-role1"), Allow,
	},
	{
		"role/service-* service-test",
		[]string{allowOn("iam:GetRole", "arn:aws:iam::123456789012:role/service-*")},
		req("iam:GetRole", "arn:aws:iam::123456789012:role/service-test"), Allow,
	},
	{
		"role/service-* admin",
		[]string{allowOn("iam:GetRole", "arn:aws:iam::123456789012:role/service-*")},
		req("iam:GetRole", "arn:aws:iam::123456789012:role/admin"), ImplicitDeny,
	},
	{
		"????-test 1234-test",
		[]string{allowOn("s3:GetObject", "arn:aws:s3:::amzn-s3-demo-bucket/????-test")},
		req("s3:GetObject", "arn:aws:s3:::amzn-s3-demo-bucket/1234-test"), Allow,
	},
	{
		"????-test a100-test",
		[]string{allowOn("s3:GetObject", "arn:aws:s3:::amzn-s3-demo-bucket/????-test")},
		req("s3:GetObject", "arn:aws:s3:::amzn-s3-demo-bucket/a100-test"), Allow,
	},
	{
		"????-test 12345-test",
		[]string{allowOn("s3:GetObject", "arn:aws:s3:::amzn-s3-demo-bucket/????-test")},
		req("s3:GetObject", "arn:aws:s3:::amzn-s3-demo-bucket/12345-test"), ImplicitDeny,
	},
	{
		"vpc in any region",
		[]string{allowOn("ec2:DescribeVpcs", "arn:aws:ec2:*:123456789012:vpc/*")},
		req(
			"ec2:DescribeVpcs",
			"arn:aws:ec2:eu-west-1:123456789012:vpc/vpc-0e9801d129EXAMPLE",
		),
		Allow,
	},
	{
		"vpc in another account",
		[]string{allowOn("ec2:DescribeVpcs", "arn:aws:ec2:*:123456789012:vpc/*")},
		req(
			"ec2:DescribeVpcs",
			"arn:aws:ec2:eu-west-1:999999999999:vpc/vpc-0e9801d129EXAMPLE",
		),
		ImplicitDeny,
	},
	// "specifying arn:aws:sqs is equivalent to arn:aws:sqs:*:*:*"
	{
		"incomplete arn",
		[]string{allowOn("sqs:SendMessage", "arn:aws:sqs")},
		req("sqs:SendMessage", "arn:aws:sqs:us-east-2:123456789012:queue1"), Allow,
	},
	{
		"incomplete arn other service",
		[]string{allowOn("sqs:SendMessage", "arn:aws:sqs")},
		req("sqs:SendMessage", "arn:aws:sns:us-east-2:123456789012:queue1"), ImplicitDeny,
	},
	// Resource page: "In the Resource element, the IAM user name is case
	// sensitive."
	{
		"user name case",
		[]string{allowOn("iam:GetUser", "arn:aws:iam::123456789012:user/Bob")},
		req("iam:GetUser", "arn:aws:iam::123456789012:user/bob"), ImplicitDeny,
	},
}

// "IAM JSON policy elements: Action",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html.
var actionPageCases = []evalCase{
	// "iam:ListAccessKeys is the same as IAM:listaccesskeys"
	{
		"case insensitive",
		[]string{allowOn("iam:ListAccessKeys", "*")},
		req("IAM:listaccesskeys", "*"),
		Allow,
	},
	{
		"case insensitive policy",
		[]string{allowOn("IAM:listaccesskeys", "*")},
		req("iam:ListAccessKeys", "*"),
		Allow,
	},
	// "applies to all IAM actions that include the string AccessKey,
	// including CreateAccessKey, DeleteAccessKey, ListAccessKeys, and
	// UpdateAccessKey."
	{
		"*AccessKey* create",
		[]string{allowOn("iam:*AccessKey*", "*")},
		req("iam:CreateAccessKey", "*"),
		Allow,
	},
	{
		"*AccessKey* delete",
		[]string{allowOn("iam:*AccessKey*", "*")},
		req("iam:DeleteAccessKey", "*"),
		Allow,
	},
	{
		"*AccessKey* list",
		[]string{allowOn("iam:*AccessKey*", "*")},
		req("iam:ListAccessKeys", "*"),
		Allow,
	},
	{
		"*AccessKey* update",
		[]string{allowOn("iam:*AccessKey*", "*")},
		req("iam:UpdateAccessKey", "*"),
		Allow,
	},
	{
		"*AccessKey* other",
		[]string{allowOn("iam:*AccessKey*", "*")},
		req("iam:CreateUser", "*"),
		ImplicitDeny,
	},
	// "the following Action element applies to all S3 actions."
	{"s3:* s3", []string{allowOn("s3:*", "*")}, req("s3:GetObject", "*"), Allow},
	{"s3:* sqs", []string{allowOn("s3:*", "*")}, req("sqs:SendMessage", "*"), ImplicitDeny},
	{"? one character", []string{allowOn("s3:Get?bject", "*")}, req("s3:GetObject", "*"), Allow},
}

const (
	notActionIAM = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}}`
	notActionS3  = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","NotAction":"s3:DeleteBucket",` +
		`"Resource":"arn:aws:s3:::*"}}`
	denyNoMFA = `{"Version":"2012-10-17","Statement":[{"Sid":"DenyAllUsersNotUsingMFA","Effect":"Deny",` +
		`"NotAction":"iam:*","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`
	denyPayroll = `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:*",` +
		`"NotResource":["arn:aws:s3:::HRBucket/Payroll","arn:aws:s3:::HRBucket/Payroll/*"]}}`
)

func withCtx(r Request, c map[string][]string) Request {
	r.Context = c
	return r
}

// "IAM JSON policy elements: NotAction",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html,
// and "IAM JSON policy elements: NotResource",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html.
var notElementCases = []evalCase{
	// "allows users to access every action in every AWS service except for
	// IAM."
	{"NotAction iam:* ec2", []string{notActionIAM}, req("ec2:RunInstances", "*"), Allow},
	{"NotAction iam:* iam", []string{notActionIAM}, req("iam:CreateUser", "*"), ImplicitDeny},
	// "allows users to access all of the Amazon S3 actions that can be
	// performed on any S3 resource except for deleting a bucket. This
	// policy also does not allow actions in other services"
	{
		"NotAction DeleteBucket get",
		[]string{notActionS3},
		req("s3:GetObject", "arn:aws:s3:::b/k"),
		Allow,
	},
	{
		"NotAction DeleteBucket delete",
		[]string{notActionS3},
		req("s3:DeleteBucket", "arn:aws:s3:::b"),
		ImplicitDeny,
	},
	{
		"NotAction DeleteBucket ec2",
		[]string{notActionS3},
		req("ec2:RunInstances", "arn:aws:ec2:us-east-1:123456789012:instance/i-1"), ImplicitDeny,
	},
	// "denies access to non-IAM actions if the user is not signed in using
	// MFA. If the user is signed in with MFA, then the Condition test
	// fails and the final Deny statement has no effect."
	{
		"no MFA non-IAM",
		[]string{allowAll, denyNoMFA},
		withCtx(req("s3:GetObject", "*"), ctx("aws:MultiFactorAuthPresent", "false")), ExplicitDeny,
	},
	{"no MFA key non-IAM", []string{allowAll, denyNoMFA}, req("s3:GetObject", "*"), ExplicitDeny},
	{"no MFA IAM", []string{allowAll, denyNoMFA}, req("iam:ListUsers", "*"), Allow},
	{
		"MFA non-IAM",
		[]string{allowAll, denyNoMFA},
		withCtx(req("s3:GetObject", "*"), ctx("aws:MultiFactorAuthPresent", "true")), Allow,
	},
	// "explicitly denies access to all Amazon S3 resources other than the
	// listed resources. Note, however, that this policy does not grant
	// the user access to any resources."
	{
		"NotResource other bucket",
		[]string{allowAll, denyPayroll},
		req("s3:GetObject", "arn:aws:s3:::HRBucket/Other/x"),
		ExplicitDeny,
	},
	{
		"NotResource payroll",
		[]string{allowAll, denyPayroll},
		req("s3:GetObject", "arn:aws:s3:::HRBucket/Payroll/x"),
		Allow,
	},
	{
		"NotResource payroll alone",
		[]string{denyPayroll},
		req("s3:GetObject", "arn:aws:s3:::HRBucket/Payroll/x"),
		ImplicitDeny,
	},
}

const homeDirPolicy = `{
  "Version":"2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["s3:ListAllMyBuckets", "s3:GetBucketLocation"], "Resource": "arn:aws:s3:::*"},
    {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::amzn-s3-demo-bucket",
     "Condition": {"StringLike": {"s3:prefix": ["", "home/", "home/${aws:username}/"]}}},
    {"Effect": "Allow", "Action": "s3:*",
     "Resource": ["arn:aws:s3:::amzn-s3-demo-bucket/home/${aws:username}",
                  "arn:aws:s3:::amzn-s3-demo-bucket/home/${aws:username}/*"]}
  ]
}`

const (
	martha = "arn:aws:iam::111122223333:user/martha_rivera"
	bucket = "arn:aws:s3:::amzn-s3-demo-bucket"
)

func listAs(principal, prefix string) Request {
	return Request{
		Action:    "s3:ListBucket",
		Resource:  bucket,
		Principal: principal,
		Context:   ctx("s3:prefix", prefix),
	}
}

func getAs(key string) Request {
	return Request{Action: "s3:GetObject", Resource: bucket + "/" + key, Principal: martha}
}

// "IAM policy elements: Variables and tags",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html,
// the operators page's "Example using a policy variable with a string
// condition operator", and "Troubleshoot IAM policies", missing JSON
// version element.
var variableCases = []evalCase{
	// operators: aws:username martha_rivera makes the condition
	// "home/martha_rivera/"; without aws:username, "No match".
	{"home prefix own", []string{homeDirPolicy}, listAs(martha, "home/martha_rivera/"), Allow},
	{
		"home prefix other",
		[]string{homeDirPolicy},
		listAs(martha, "home/nikki_wolf/"),
		ImplicitDeny,
	},
	{
		"home prefix no username",
		[]string{homeDirPolicy},
		listAs("arn:aws:iam::111122223333:role/r", "home/martha_rivera/"), ImplicitDeny,
	},
	{
		"home object own",
		[]string{homeDirPolicy},
		getAs("home/martha_rivera/notes.txt"),
		Allow,
	},
	{
		"home object other",
		[]string{homeDirPolicy},
		getAs("home/nikki_wolf/notes.txt"),
		ImplicitDeny,
	},
	// variables: "Access is explicitly denied when aws:principaltag/Team
	// is not set."
	{
		"team tag unset",
		[]string{allowAll, `{"Version":"2012-10-17","Statement":[{"Effect":"Deny",` +
			`"Action":"s3:GetObject","Resource":"arn:aws:s3:::amzn-s3-demo-bucket/*","Condition":{"StringNotEquals":` +
			`{"s3:ExistingObjectTag/Team":"${aws:PrincipalTag/Team}"}}}]}`},
		withCtx(getAs("k"), ctx("s3:ExistingObjectTag/Team", "red")), ExplicitDeny,
	},
	{
		"team tag equal",
		[]string{allowAll, `{"Version":"2012-10-17","Statement":[{"Effect":"Deny",` +
			`"Action":"s3:GetObject","Resource":"arn:aws:s3:::amzn-s3-demo-bucket/*","Condition":{"StringNotEquals":` +
			`{"s3:ExistingObjectTag/Team":"${aws:PrincipalTag/Team}"}}}]}`},
		withCtx(
			getAs("k"),
			ctx("s3:ExistingObjectTag/Team", "red", "aws:PrincipalTag/Team", "red"),
		),
		Allow,
	},
	// variables, specifying default values: team=yellow reaches
	// amzn-s3-demo-bucket-yellow; "For users without team tags, it sets a
	// default value of company-wide for the bucket name."
	{
		"default value tagged",
		[]string{allowOn("s3:GetObject",
			"arn:aws:s3:::amzn-s3-demo-bucket-${aws:PrincipalTag/team, 'company-wide'}")},
		withCtx(
			req("s3:GetObject", "arn:aws:s3:::amzn-s3-demo-bucket-yellow"),
			ctx("aws:PrincipalTag/team", "yellow"),
		),
		Allow,
	},
	{
		"default value untagged",
		[]string{allowOn("s3:GetObject",
			"arn:aws:s3:::amzn-s3-demo-bucket-${aws:PrincipalTag/team, 'company-wide'}")},
		req("s3:GetObject", "arn:aws:s3:::amzn-s3-demo-bucket-company-wide"), Allow,
	},
	{
		"default value untagged other",
		[]string{allowOn("s3:GetObject",
			"arn:aws:s3:::amzn-s3-demo-bucket-${aws:PrincipalTag/team, 'company-wide'}")},
		req("s3:GetObject", "arn:aws:s3:::amzn-s3-demo-bucket-yellow"), ImplicitDeny,
	},
	// Troubleshoot: without a Version, "${aws:username}" is a literal
	// string, so the user's own ARN does not match.
	{
		"no version literal",
		[]string{`{"Statement":{"Action":"iam:*AccessKey*","Effect":"Allow",` +
			`"Resource":"arn:aws:iam::123456789012:user/${aws:username}"}}`},
		req("iam:CreateAccessKey", "arn:aws:iam::123456789012:user/alice"), ImplicitDeny,
	},
	{
		"version variable",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Action":"iam:*AccessKey*","Effect":"Allow",` +
				`"Resource":"arn:aws:iam::123456789012:user/${aws:username}"}}`,
		},
		req("iam:CreateAccessKey", "arn:aws:iam::123456789012:user/alice"),
		Allow,
	},
}

// operators, wildcard matching example: the table's "Match" is the
// request staying inside the boundary, which is the Deny statement's
// ForAllValues:StringNotLike condition not holding; "No match" is the
// request outside it, denied. A missing aws:ResourceOrgPaths makes
// ForAllValues hold, so the Deny applies.
var orgBoundaryCases = func() []evalCase {
	deny := `{"Version":"2012-10-17","Statement":[{"Sid":"DenyS3AccessOutsideMyBoundary","Effect":"Deny",` +
		`"Action":["s3:*"],"Resource":"*","Condition":{"ForAllValues:StringNotLike":{"aws:ResourceOrgPaths":[` +
		`"o-acorg/r-acroot/ou-acroot-mediaou/","o-acorg/r-acroot/ou-acroot-sportsou/*"]}}}]}`
	ps := []string{allowAll, deny}
	r := req("s3:GetObject", "arn:aws:s3:::b/k")
	return []evalCase{
		{
			"sportsou",
			ps,
			withCtx(
				r,
				ctx("aws:ResourceOrgPaths", "o-acorg/r-acroot/ou-acroot-sportsou/costcenter/"),
			),
			Allow,
		},
		{
			"mediaou",
			ps,
			withCtx(
				r,
				ctx("aws:ResourceOrgPaths", "o-acorg/r-acroot/ou-acroot-mediaou/costcenter/"),
			),
			ExplicitDeny,
		},
		{"missing", ps, r, ExplicitDeny},
	}
}()

func TestDocumentedExamples(t *testing.T) {
	t.Run("resource wildcards", func(t *testing.T) { runEvalCases(t, resourceWildcardCases) })
	t.Run("arn paths", func(t *testing.T) { runEvalCases(t, arnPageCases) })
	t.Run("action", func(t *testing.T) { runEvalCases(t, actionPageCases) })
	t.Run("not elements", func(t *testing.T) { runEvalCases(t, notElementCases) })
	t.Run("variables", func(t *testing.T) { runEvalCases(t, variableCases) })
	t.Run("org boundary", func(t *testing.T) { runEvalCases(t, orgBoundaryCases) })
}
