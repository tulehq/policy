package policy_test

// Conformance rows for requests made by AWS service principals, evaluated
// with AuthorizeService, written from AWS documentation as
// conformance_resource_test.go is. Every row names the page it comes from
// and the outcome that page states. Rows whose outcome AWS does not state
// outright are marked "CHOICE:" (this package's documented choice) or
// "ASSUMPTION:" with the reasoning.

import (
	"testing"

	"tule.dev/policy"
)

const (
	docS3Notify      = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/grant-destinations-permissions-to-s3.html"
	docS3BlockPublic = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
	docSNSToSQS      = "https://docs.aws.amazon.com/sns/latest/dg/sns-send-message-to-sqs-cross-account.html"
	docSNSUseCases   = "https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html"
)

const (
	spSecrets  = "secretsmanager.amazonaws.com"
	spS3       = "s3.amazonaws.com"
	spFunction = "arn:aws:lambda:us-east-1:111122223333:function:rotate"
	spRotated  = "arn:aws:secretsmanager:us-east-1:111122223333:secret:db-AbCdEf"
	spTopic    = "arn:aws:sns:us-east-1:111122223333:example-sns-topic"
	spQueue    = "arn:aws:sqs:us-east-1:111122223333:queue-name"
	spBucket   = "arn:aws:s3:::amzn-s3-demo-bucket"
)

// spFunctionAllow is a function policy with one Allow statement: the
// principal element and an optional Condition element. Its action is
// lambda:InvokeFunction and its resource spFunction.
func spFunctionAllow(principal, condition string) string {
	c := ""
	if condition != "" {
		c = `,"Condition":` + condition
	}
	return `{"Version":"2012-10-17","Statement":{"Sid":"Fn","Effect":"Allow",` + principal +
		`,"Action":"lambda:InvokeFunction","Resource":"` + spFunction + `"` + c + `}}`
}

// spRotation is the grant that lets Secrets Manager invoke a rotation
// function, scoped to one secret.
var spRotation = spFunctionAllow(`"Principal":{"Service":"`+spSecrets+`"}`,
	`{"ArnEquals":{"aws:SourceArn":"`+spRotated+`"}}`)

// spWithDeny is spRotation's statement and a second statement, in that
// order.
func spWithDeny(second string) string {
	return `{"Version":"2012-10-17","Statement":[{"Sid":"Fn","Effect":"Allow",` +
		`"Principal":{"Service":"` + spSecrets + `"},"Action":"lambda:InvokeFunction","Resource":"` +
		spFunction + `"},` + second + `]}`
}

// spCase is one AuthorizeService request. resource entries ending in
// ".json" name files in testdata/aws; others are the documents. An empty
// resource means the resource has no resource-based policy.
//
//nolint:govet // fieldalignment: field order reads as the table rows do.
type spCase struct {
	name     string
	src      string // AWS page
	stated   string // outcome as AWS states it
	resource string
	service  string // spSecrets when empty
	action   string // lambda:InvokeFunction when empty
	res      string // spFunction when empty
	ctx      cfCtx
	unknown  []string
	want     policy.Decision
	reason   policy.Reason
	sid      string // the deciding statement's Sid, when one decides
}

func spRun(t *testing.T, cases []spCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var rp *policy.Policy
			if c.resource != "" {
				rp = rpLoad(t, c.resource, policy.ParseResource)
			}
			req := policy.ServiceRequest{
				Action: or(c.action, "lambda:InvokeFunction"), Resource: or(c.res, spFunction),
				Service: or(c.service, spSecrets), Context: c.ctx, Unknown: c.unknown,
			}
			got := policy.AuthorizeService(req, rp)
			if got.Decision != c.want || got.Reason != c.reason {
				t.Errorf(
					"AuthorizeService = %v, %v; want %v, %v\n  service: %s\n  source: %s\n  AWS states: %s",
					got.Decision,
					got.Reason,
					c.want,
					c.reason,
					req.Service,
					c.src,
					c.stated,
				)
			}
			spCheck(t, got, c.sid)
		})
	}
}

// spCheck checks the invariants of one AuthorizeService result: Identity
// is always the empty ImplicitDeny, Direct is set exactly for an Allow,
// and Resource is the deciding statement's or -1.
func spCheck(t *testing.T, got policy.Authorization, sid string) {
	t.Helper()
	none := policy.Result{Decision: policy.ImplicitDeny, Policy: -1}
	if got.Identity != none {
		t.Errorf("Identity = %+v, want %+v", got.Identity, none)
	}
	if got.Direct != (got.Decision == policy.Allow) {
		t.Errorf("Direct = %v for %v", got.Direct, got.Decision)
	}
	want := none
	if got.Decision != policy.ImplicitDeny {
		want = policy.Result{Decision: got.Decision, Policy: 0, Sid: sid}
	}
	if got.Resource != want {
		t.Errorf("Resource = %+v, want %+v", got.Resource, want)
	}
}

// ---------------------------------------------------------------------------
// Principal matching

var spPrincipalCases = []spCase{
	{
		name:     "rotation grant: Secrets Manager invokes for its secret",
		src:      docPrincipal + ", " + docCondKeys,
		stated:   "You can specify AWS services in the Principal element of a resource-based policy",
		resource: spRotation,
		ctx:      cfCtx{"aws:SourceArn": {spRotated}},
		want:     policy.Allow,
		sid:      "Fn",
	},
	{
		name:     "another service is not named",
		src:      docPrincipal,
		stated:   "A service principal is an identifier for a service.",
		resource: spRotation,
		service:  spS3,
		ctx:      cfCtx{"aws:SourceArn": {spRotated}},
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:   "an array of service principals names each",
		src:    docPrincipal,
		stated: "you use an array of multiple service principals as the value of a single Service element",
		resource: spFunctionAllow(
			`"Principal":{"Service":["ecs.amazonaws.com","elasticloadbalancing.amazonaws.com"]}`,
			"",
		),
		service: "elasticloadbalancing.amazonaws.com",
		want:    policy.Allow,
		sid:     "Fn",
	},
	{
		name:     "regional name in the request, non-regional in the policy",
		src:      docPrincipal,
		stated:   "If you specify the non-regionalized version of the S3 service principal ... the sns:Publish request from the bucket to the topic will fail.",
		resource: spFunctionAllow(`"Principal":{"Service":"s3.amazonaws.com"}`, ""),
		service:  "s3.ap-east-1.amazonaws.com",
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:     "regional name in the request and the policy",
		src:      docPrincipal,
		stated:   "After you specify the regionalized service principal name ... the request will be successful.",
		resource: spFunctionAllow(`"Principal":{"Service":"s3.ap-east-1.amazonaws.com"}`, ""),
		service:  "s3.ap-east-1.amazonaws.com",
		want:     policy.Allow,
		sid:      "Fn",
	},
	{
		name: `Allow "*" names a service`,
		src:  docS3BlockPublic,
		stated: "restricts access to an access point or bucket with a public policy to only AWS service principals " +
			"and authorized users within the bucket owner's account",
		resource: spFunctionAllow(`"Principal":"*"`, ""),
		want:     policy.Allow,
		sid:      "Fn",
	},
	{
		name:     `Allow {"AWS":"*"} names a service`,
		src:      docSNSUseCases,
		stated:   `"Allow any CloudWatch alarm to publish to a topic in a different account": {"AWS":"*"} with aws:SourceArn`,
		resource: spFunctionAllow(`"Principal":{"AWS":"*"}`, ""),
		want:     policy.Allow,
		sid:      "Fn",
	},
	{
		name:     `Allow {"AWS":"*"} with the Service value names it`,
		src:      docPrincipal,
		stated:   "When you specify more than one principal in an element, you grant permissions to each principal.",
		resource: spFunctionAllow(`"Principal":{"AWS":"*","Service":"`+spSecrets+`"}`, ""),
		want:     policy.Allow,
		sid:      "Fn",
	},
	{
		name:     "an account principal does not name a service",
		src:      docPrincipal,
		stated:   "This delegates authority to the account. ASSUMPTION: a service principal is in no account",
		resource: spFunctionAllow(`"Principal":{"AWS":"111122223333"}`, ""),
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:     "no resource-based policy",
		src:      docEvalLogic,
		stated:   "ASSUMPTION: a service principal has no identity-based policies, so nothing allows",
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
		resource: "",
	},
}

func TestConformanceServicePrincipal(t *testing.T) { spRun(t, spPrincipalCases) }

// ---------------------------------------------------------------------------
// Deny, "*" and NotPrincipal

var spDenyCases = []spCase{
	{
		name:     "Deny for all service principals but CodeBuild: CodeBuild",
		src:      docNotPrincipal,
		stated:   "prevent all service principals, except those specified in the Condition element",
		resource: "deny-not-codebuild.json",
		service:  "codebuild.amazonaws.com",
		action:   "s3:GetObject",
		res:      "arn:aws:s3:::BUCKETNAME/key",
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:     `Deny for all service principals but CodeBuild: another service`,
		src:      docNotPrincipal,
		stated:   `a Deny with "Principal": "*" reaches service principals`,
		resource: "deny-not-codebuild.json",
		service:  "cloudtrail.amazonaws.com",
		action:   "s3:GetObject",
		res:      "arn:aws:s3:::BUCKETNAME/key",
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
		sid:      "DenyNotCodeBuildAccess",
	},
	{
		name:   `Deny {"AWS":"*"} names a service`,
		src:    docNotPrincipal,
		stated: `{"AWS":"*"} as "*", which in a Deny reaches service principals`,
		resource: spWithDeny(`{"Sid":"D","Effect":"Deny","Principal":{"AWS":"*"},` +
			`"Action":"lambda:InvokeFunction","Resource":"*"}`),
		want:   policy.ExplicitDeny,
		reason: policy.ResourceDeny,
		sid:    "D",
	},
	{
		name:   "Deny on the service wins over its Allow",
		src:    docEvalLogic,
		stated: "an explicit deny in any of these policies overrides the allow",
		resource: spWithDeny(
			`{"Sid":"D","Effect":"Deny","Principal":{"Service":"` + spSecrets + `"},` +
				`"Action":"lambda:*","Resource":"*"}`,
		),
		want:   policy.ExplicitDeny,
		reason: policy.ResourceDeny,
		sid:    "D",
	},
	{
		name:   "Deny on another service does not apply",
		src:    docPrincipal,
		stated: "A service principal is an identifier for a service.",
		resource: spWithDeny(`{"Sid":"D","Effect":"Deny","Principal":{"Service":"` + spS3 + `"},` +
			`"Action":"lambda:*","Resource":"*"}`),
		want: policy.Allow,
		sid:  "Fn",
	},
	{
		name:   "NotPrincipal naming the service exempts it",
		src:    docNotPrincipal,
		stated: "deny access to all principals except the principal specified in the NotPrincipal element. A principal can be ... AWS service",
		resource: spWithDeny(
			`{"Sid":"D","Effect":"Deny","NotPrincipal":{"Service":"` + spSecrets + `"},` +
				`"Action":"lambda:*","Resource":"*"}`,
		),
		want: policy.Allow,
		sid:  "Fn",
	},
	{
		name:   "NotPrincipal naming another service denies",
		src:    docNotPrincipal,
		stated: "deny access to all principals except the principal specified in the NotPrincipal element",
		resource: spWithDeny(
			`{"Sid":"D","Effect":"Deny","NotPrincipal":{"Service":"` + spS3 + `"},` +
				`"Action":"lambda:*","Resource":"*"}`,
		),
		want:   policy.ExplicitDeny,
		reason: policy.ResourceDeny,
		sid:    "D",
	},
	{
		name:   "NotPrincipal naming an account does not exempt a service",
		src:    docNotPrincipal,
		stated: "ASSUMPTION: a service principal is in no account",
		resource: spWithDeny(`{"Sid":"D","Effect":"Deny","NotPrincipal":{"AWS":"111122223333"},` +
			`"Action":"lambda:*","Resource":"*"}`),
		want:   policy.ExplicitDeny,
		reason: policy.ResourceDeny,
		sid:    "D",
	},
	{
		name: `NotPrincipal "*" exempts a service`,
		src:  docNotPrincipal,
		stated: `deny access to all principals except the principal specified in the NotPrincipal element. ` +
			`CHOICE: "*" names every principal, as Authorize exempts every caller`,
		resource: spWithDeny(`{"Sid":"D","Effect":"Deny","NotPrincipal":"*",` +
			`"Action":"lambda:*","Resource":"*"}`),
		want: policy.Allow,
		sid:  "Fn",
	},
}

func TestConformanceServiceDeny(t *testing.T) { spRun(t, spDenyCases) }

// ---------------------------------------------------------------------------
// Action and Resource

var spElementCases = []spCase{
	{
		name:     "another action",
		src:      docAction,
		stated:   "ASSUMPTION: the statement names only lambda:InvokeFunction",
		resource: spFunctionAllow(`"Principal":{"Service":"`+spSecrets+`"}`, ""),
		action:   "lambda:GetFunction",
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:     "action names are case-insensitive",
		src:      docAction,
		stated:   "The prefix and the action name are case insensitive.",
		resource: "sns-topic-s3-notification.json",
		service:  spS3,
		action:   "sns:publish",
		res:      spTopic,
		ctx:      cfCtx{"aws:SourceArn": {spBucket}, "aws:SourceAccount": {"123456789012"}},
		want:     policy.Allow,
		sid:      "Example SNS topic policy",
	},
	{
		name:   "NotAction excludes the action",
		src:    docNotAction,
		stated: "explicitly matches everything except the specified list of actions",
		resource: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"` + spSecrets +
			`"},"NotAction":"lambda:InvokeFunction","Resource":"*"}}`,
		want:   policy.ImplicitDeny,
		reason: policy.NoResourceAllow,
	},
	{
		name:     "another resource",
		src:      docResource,
		stated:   "ASSUMPTION: the statement names only spFunction",
		resource: spFunctionAllow(`"Principal":{"Service":"`+spSecrets+`"}`, ""),
		res:      "arn:aws:lambda:us-east-1:111122223333:function:other",
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:   "NotResource excludes the resource",
		src:    docNotResource,
		stated: "explicitly matches every resource except those specified",
		resource: `{"Version":"2012-10-17","Statement":{"Sid":"N","Effect":"Allow","Principal":{"Service":"` +
			spSecrets + `"},"Action":"lambda:InvokeFunction","NotResource":"` + spFunction + `"}}`,
		want:   policy.ImplicitDeny,
		reason: policy.NoResourceAllow,
	},
	{
		name:   "NotResource covers another resource",
		src:    docNotResource,
		stated: "explicitly matches every resource except those specified",
		resource: `{"Version":"2012-10-17","Statement":{"Sid":"N","Effect":"Allow","Principal":{"Service":"` +
			spSecrets + `"},"Action":"lambda:InvokeFunction","NotResource":"` + spFunction + `"}}`,
		res:  "arn:aws:lambda:us-east-1:111122223333:function:other",
		want: policy.Allow,
		sid:  "N",
	},
}

func TestConformanceServiceElements(t *testing.T) { spRun(t, spElementCases) }

// ---------------------------------------------------------------------------
// Condition keys

var spSNSCtx = cfCtx{"aws:SourceArn": {spBucket}, "aws:SourceAccount": {"123456789012"}}

var spConditionCases = []spCase{
	{
		name:     "S3 notification to SNS: the configured bucket",
		src:      docS3Notify + ", " + docCondKeys,
		stated:   "In the topic policy that allows the sns:Publish operation, set the value of the condition key to the ARN of the Amazon S3 bucket.",
		resource: "sns-topic-s3-notification.json",
		service:  spS3,
		action:   "SNS:Publish",
		res:      spTopic,
		ctx:      spSNSCtx,
		want:     policy.Allow,
		sid:      "Example SNS topic policy",
	},
	{
		name:     "S3 notification to SNS: another bucket",
		src:      docCondKeys,
		stated:   "a calling service can access your resource only when the request originates from a specific resource",
		resource: "sns-topic-s3-notification.json",
		service:  spS3,
		action:   "SNS:Publish",
		res:      spTopic,
		ctx: cfCtx{
			"aws:SourceArn":     {"arn:aws:s3:::other"},
			"aws:SourceAccount": {"123456789012"},
		},
		want:   policy.ImplicitDeny,
		reason: policy.NoResourceAllow,
	},
	{
		name:     "S3 notification to SNS: another source account",
		src:      docCondKeys,
		stated:   "a calling service can access your resource only when the request originates from a specific account",
		resource: "sns-topic-s3-notification.json",
		service:  spS3,
		action:   "SNS:Publish",
		res:      spTopic,
		ctx:      cfCtx{"aws:SourceArn": {spBucket}, "aws:SourceAccount": {"444455556666"}},
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:     "S3 notification to SNS: no source keys",
		src:      docCondition,
		stated:   "If the key that you specify in a policy condition is not present in the request context, the values do not match",
		resource: "sns-topic-s3-notification.json",
		service:  spS3,
		action:   "SNS:Publish",
		res:      spTopic,
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:     "S3 notification to SQS: ArnLike with region and account wildcards",
		src:      docS3Notify,
		stated:   `"aws:SourceArn": "arn:aws:s3:*:*:amzn-s3-demo-bucket"`,
		resource: "sqs-queue-s3-notification.json",
		service:  spS3,
		action:   "sqs:SendMessage",
		res:      spQueue,
		ctx:      spSNSCtx,
		want:     policy.Allow,
		sid:      "example-statement-ID",
	},
	{
		name:   `Allow "*" scoped by aws:PrincipalServiceName: the named service`,
		src:    docCondKeys,
		stated: "the aws:PrincipalServiceName key contains the name of the service principal",
		resource: spFunctionAllow(`"Principal":"*"`,
			`{"StringEquals":{"aws:PrincipalServiceName":"`+spSecrets+`"}}`),
		want: policy.Allow,
		sid:  "Fn",
	},
	{
		name:   `Allow "*" scoped by aws:PrincipalServiceName: another service`,
		src:    docCondKeys,
		stated: "the aws:PrincipalServiceName key contains the name of the service principal",
		resource: spFunctionAllow(`"Principal":"*"`,
			`{"StringEquals":{"aws:PrincipalServiceName":"`+spSecrets+`"}}`),
		service: spS3,
		want:    policy.ImplicitDeny,
		reason:  policy.NoResourceAllow,
	},
	{
		name:     "SNS topic to SQS queue: the subscribed topic",
		src:      docSNSToSQS,
		stated:   "an example policy statement that allows the Amazon SNS topic to send a message to the Amazon SQS queue",
		resource: "sqs-queue-sns-topic.json",
		service:  "sns.amazonaws.com",
		action:   "sqs:SendMessage",
		res:      "arn:aws:sqs:us-west-2:111111111111:QueueName",
		ctx:      cfCtx{"aws:SourceArn": {"arn:aws:sns:us-west-2:555555555555:TopicName"}},
		want:     policy.Allow,
		sid:      "Stmt1234",
	},
	{
		name:     "SNS topic to SQS queue: another topic",
		src:      docSNSToSQS + ", " + docCondKeys,
		stated:   "a calling service can access your resource only when the request originates from a specific resource",
		resource: "sqs-queue-sns-topic.json",
		service:  "sns.amazonaws.com",
		action:   "sqs:SendMessage",
		res:      "arn:aws:sqs:us-west-2:111111111111:QueueName",
		ctx:      cfCtx{"aws:SourceArn": {"arn:aws:sns:us-west-2:555555555555:OtherTopic"}},
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:   "aws:PrincipalServiceName in a Service grant",
		src:    docCondKeys,
		stated: "the aws:PrincipalServiceName key contains the name of the service principal",
		resource: spFunctionAllow(`"Principal":{"Service":"`+spSecrets+`"}`,
			`{"StringEquals":{"aws:PrincipalServiceName":"`+spSecrets+`"}}`),
		ctx:  cfCtx{"aws:PrincipalServiceName": {spS3}},
		want: policy.Allow,
		sid:  "Fn",
	},
	{
		name:   "aws:PrincipalServiceName cannot be set through Context",
		src:    docCondKeys,
		stated: "CHOICE: the principal's keys replace the request context's",
		resource: spWithDeny(
			`{"Sid":"D","Effect":"Deny","Principal":"*","Action":"*","Resource":"*",` +
				`"Condition":{"StringNotEquals":{"aws:PrincipalServiceName":"codebuild.amazonaws.com"}}}`,
		),
		ctx:    cfCtx{"AWS:PrincipalServiceName": {"codebuild.amazonaws.com"}},
		want:   policy.ExplicitDeny,
		reason: policy.ResourceDeny,
		sid:    "D",
	},
	{
		name:   "aws:PrincipalIsAWSService is true",
		src:    docCondKeys,
		stated: "The request context key is set to true when a service uses a service principal to perform a direct action on your resources.",
		resource: spWithDeny(
			`{"Sid":"D","Effect":"Deny","Principal":"*","Action":"*","Resource":"*",` +
				`"Condition":{"BoolIfExists":{"aws:PrincipalIsAWSService":"false"}}}`,
		),
		ctx:  cfCtx{"aws:PrincipalIsAWSService": {"false"}},
		want: policy.Allow,
		sid:  "Fn",
	},
	{
		name:   "aws:SourceArn as a variable",
		src:    docVariables,
		stated: "You can use any single-valued condition key as a variable.",
		resource: spFunctionAllow(
			`"Principal":{"Service":"`+spSecrets+`"}`,
			`{"StringEquals":{"aws:SourceArn":"arn:aws:secretsmanager:us-east-1:${aws:SourceAccount}:secret:db-AbCdEf"}}`,
		),
		ctx:  cfCtx{"aws:SourceArn": {spRotated}, "aws:SourceAccount": {"111122223333"}},
		want: policy.Allow,
		sid:  "Fn",
	},
}

func TestConformanceServiceConditions(t *testing.T) { spRun(t, spConditionCases) }

// ---------------------------------------------------------------------------
// Keys a service principal does not have

func spAllowIf(condition string) string {
	return spFunctionAllow(`"Principal":{"Service":"`+spSecrets+`"}`, condition)
}

func spDenyIf(condition string) string {
	return spWithDeny(`{"Sid":"D","Effect":"Deny","Principal":{"Service":"` + spSecrets +
		`"},"Action":"*","Resource":"*","Condition":` + condition + `}`)
}

var spAbsentCases = []spCase{
	{
		name:     "aws:PrincipalOrgID is absent whatever Context gives",
		src:      docCondKeys,
		stated:   "This key is included in the request context only if the principal is a member of an organization.",
		resource: spAllowIf(`{"StringEquals":{"aws:PrincipalOrgID":"o-a1b2c3d4e5"}}`),
		ctx:      cfCtx{"aws:PrincipalOrgID": {"o-a1b2c3d4e5"}},
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:     "aws:PrincipalOrgPaths is absent: Null holds",
		src:      docOperators + ", " + docCondKeys,
		stated:   `"Null": true means the key is not present`,
		resource: spAllowIf(`{"Null":{"aws:PrincipalOrgPaths":"true"}}`),
		ctx:      cfCtx{"aws:PrincipalOrgPaths": {"o-a1b2c3d4e5/r-ab12/"}},
		want:     policy.Allow,
		sid:      "Fn",
	},
	{
		name:     "aws:username is absent: Null holds",
		src:      docVariables,
		stated:   "aws:username is present for IAM users only",
		resource: spAllowIf(`{"Null":{"aws:username":"true"}}`),
		ctx:      cfCtx{"aws:username": {"admin"}},
		want:     policy.Allow,
		sid:      "Fn",
	},
	{
		name:     "aws:PrincipalTag keys are absent",
		src:      docCondKeys,
		stated:   "This key is included in the request context if the principal is using an IAM user with attached tags.",
		resource: spAllowIf(`{"StringEquals":{"aws:PrincipalTag/team":"ops"}}`),
		ctx:      cfCtx{"aws:PrincipalTag/team": {"ops"}},
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:   "aws:PrincipalArn is unknown: an Allow on it does not apply",
		src:    docCondKeys,
		stated: "included in the request context for all signed requests. CHOICE: its value for a service is undocumented, so it is unknown",
		resource: spAllowIf(
			`{"ArnNotEquals":{"aws:PrincipalArn":"arn:aws:iam::111122223333:role/x"}}`,
		),
		ctx:    cfCtx{"aws:PrincipalArn": {"arn:aws:iam::111122223333:role/y"}},
		want:   policy.ImplicitDeny,
		reason: policy.NoResourceAllow,
	},
	{
		name:     "aws:PrincipalArn is unknown: Null in an Allow does not hold",
		src:      docCondKeys,
		stated:   "CHOICE: an unknown key is neither present nor absent",
		resource: spAllowIf(`{"Null":{"aws:PrincipalArn":"true"}}`),
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:     "aws:PrincipalAccount is unknown: a Deny on it applies",
		src:      docCondKeys,
		stated:   "included in the request context for all requests, including anonymous requests. CHOICE: unknown",
		resource: spDenyIf(`{"StringEquals":{"aws:PrincipalAccount":"999999999999"}}`),
		ctx:      cfCtx{"aws:PrincipalAccount": {"111122223333"}},
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
		sid:      "D",
	},
	{
		name:     "aws:PrincipalType is unknown",
		src:      docVariables,
		stated:   "CHOICE: the principal table has no row for a service principal",
		resource: spAllowIf(`{"StringNotEquals":{"aws:PrincipalType":"User"}}`),
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:     "aws:userid is unknown",
		src:      docVariables,
		stated:   "CHOICE: the principal table has no row for a service principal",
		resource: spDenyIf(`{"StringLike":{"aws:userid":"AIDA*"}}`),
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
		sid:      "D",
	},
	{
		name: "the Deny-all-but-named-user example denies a service",
		src:  docPrincipal,
		stated: "explicitly deny all principals except for the ones specified in the Condition element. " +
			"CHOICE: aws:PrincipalArn is unknown, so the Deny applies",
		resource: "principal-arn-instead-of-notprincipal.json",
		service:  spS3,
		action:   "s3:GetObject",
		res:      rpObject,
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
		sid:      "UsePrincipalArnInsteadOfNotPrincipalWithDeny",
	},
}

func TestConformanceServiceAbsentKeys(t *testing.T) { spRun(t, spAbsentCases) }

// ---------------------------------------------------------------------------
// Unknown keys

var spUnknownCases = []spCase{
	{
		name:     "unknown aws:SourceArn: the grant does not apply",
		src:      docCondKeys,
		stated:   "CHOICE: an unknown key never helps an Allow apply",
		resource: spRotation,
		ctx:      cfCtx{"aws:SourceArn": {spRotated}},
		unknown:  []string{"aws:SourceArn"},
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:     "unknown aws:SourceAccount: a Deny on it applies",
		src:      docCondKeys,
		stated:   "CHOICE: an unknown key always helps a Deny apply",
		resource: spDenyIf(`{"StringNotEquals":{"aws:SourceAccount":"111122223333"}}`),
		ctx:      cfCtx{"aws:SourceAccount": {"111122223333"}},
		unknown:  []string{"aws:sourceaccount"},
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
		sid:      "D",
	},
	{
		name:     "Unknown applies to the principal's keys",
		src:      docCondKeys,
		stated:   "CHOICE: as in Authorize, Unknown applies to the keys that come from the principal",
		resource: spAllowIf(`{"StringEquals":{"aws:PrincipalServiceName":"` + spSecrets + `"}}`),
		unknown:  []string{"aws:PrincipalServiceName"},
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:     "unknown variable in Resource of an Allow",
		src:      docVariables,
		stated:   "CHOICE: an entry whose variable names an unknown key is dropped in an Allow",
		resource: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"` + spSecrets + `"},"Action":"lambda:InvokeFunction","Resource":"` + spFunction + `-${aws:SourceAccount}"}}`,
		res:      spFunction + "-111122223333",
		ctx:      cfCtx{"aws:SourceAccount": {"111122223333"}},
		unknown:  []string{"aws:SourceAccount"},
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
}

func TestConformanceServiceUnknown(t *testing.T) { spRun(t, spUnknownCases) }

// ---------------------------------------------------------------------------
// Invalid service principals

func TestConformanceServiceInvalid(t *testing.T) {
	rp := rpLoad(
		t,
		spWithDeny(`{"Sid":"D","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}`),
		policy.ParseResource,
	)
	for _, service := range []string{
		"", "*", "secretsmanager", "secretsmanager.*.com", "s?.amazonaws.com", "secrets manager.amazonaws.com",
		"arn:aws:iam::111122223333:root", "111122223333",
	} {
		t.Run(service, func(t *testing.T) {
			got := policy.AuthorizeService(policy.ServiceRequest{
				Action: "lambda:InvokeFunction", Resource: spFunction, Service: service,
			}, rp)
			if got.Decision != policy.ImplicitDeny || got.Reason != policy.NoResourceAllow {
				t.Errorf(
					"AuthorizeService(%q) = %v, %v; want ImplicitDeny, NoResourceAllow\n  source: %s\n"+
						"  AWS states: the identifier for a service principal ... is usually service-name.amazonaws.com. "+
						"CHOICE: an invalid Service value is refused before any statement is read",
					service,
					got.Decision,
					got.Reason,
					docPrincipal,
				)
			}
			spCheck(t, got, "")
		})
	}
}

// Statements that are not resource-based statements never apply, though
// the lenient Parse accepts them.
func TestConformanceServiceIgnoresOtherKinds(t *testing.T) {
	for _, doc := range []string{
		// No Principal: an identity-based statement.
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		// No Resource: a trust statement.
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"` + spSecrets +
			`"},"Action":"*"}}`,
	} {
		p, err := policy.Parse([]byte(doc))
		if err != nil {
			t.Fatalf("Parse(%s): %v", doc, err)
		}
		got := policy.AuthorizeService(policy.ServiceRequest{
			Action: "lambda:InvokeFunction", Resource: spFunction, Service: spSecrets,
		}, p)
		if got.Decision != policy.ImplicitDeny || got.Reason != policy.NoResourceAllow {
			t.Errorf(
				"AuthorizeService against %s = %v, %v; want ImplicitDeny, NoResourceAllow\n  source: %s",
				doc,
				got.Decision,
				got.Reason,
				docPrincipal,
			)
		}
	}
}

// ---------------------------------------------------------------------------
// Authorize is unchanged for statements that name only a service

var spAuthorizeCases = []rpCase{
	{
		name:     "Allow to a service grants a caller nothing",
		src:      docPrincipal,
		stated:   "ASSUMPTION: no Caller is a service",
		resource: rpBucket("Allow", `"Principal":{"Service":"s3.amazonaws.com"}`, ""),
		caller:   rpPartner,
		account:  rpAcct,
		identity: []string{rpAllowGet},
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:     "Deny to a service does not deny a caller",
		src:      docPrincipal,
		stated:   "ASSUMPTION: no Caller is a service",
		resource: rpBucket("Deny", `"Principal":{"Service":"s3.amazonaws.com"}`, ""),
		caller:   rpDev,
		identity: []string{rpAllowGet},
		want:     policy.Allow,
	},
	{
		name:     "NotPrincipal naming a service does not exempt a caller",
		src:      docNotPrincipal,
		stated:   "deny access to all principals except the principal specified in the NotPrincipal element",
		resource: rpBucket("Deny", `"NotPrincipal":{"Service":"s3.amazonaws.com"}`, ""),
		caller:   rpDev,
		identity: []string{rpAllowGet},
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
	},
}

func TestConformanceServiceAuthorizeUnchanged(t *testing.T) { rpRun(t, spAuthorizeCases) }

// A Caller is never a service principal, whatever its request context
// says.
var spCallerKeyCases = []rpCase{
	{
		name:   "aws:PrincipalIsAWSService true in Context does not grant a caller",
		src:    docCondKeys,
		stated: `The context key is set to false if the service uses the credentials of an IAM principal`,
		resource: rpBucket("Allow", `"Principal":"*"`,
			`{"Bool":{"aws:PrincipalIsAWSService":"true"}}`),
		caller:   rpPartner,
		identity: []string{rpAllowGet},
		ctx:      cfCtx{"aws:PrincipalIsAWSService": {"true"}},
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:   "aws:PrincipalIsAWSService is false for a caller without Context",
		src:    docCondKeys,
		stated: "This key is present in the request context for all signed API requests that use AWS credentials.",
		resource: rpBucket("Deny", `"Principal":"*"`,
			`{"Bool":{"aws:PrincipalIsAWSService":"false"}}`),
		caller:   rpDev,
		identity: []string{rpAllowGet},
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
	},
	{
		name:   "aws:PrincipalIsAWSService false wins over Context",
		src:    docCondKeys,
		stated: `The context key is set to false if the service uses the credentials of an IAM principal`,
		resource: rpBucket("Deny", `"Principal":"*"`,
			`{"BoolIfExists":{"aws:PrincipalIsAWSService":"false"}}`),
		caller:   rpDev,
		identity: []string{rpAllowGet},
		ctx:      cfCtx{"AWS:principalisawsservice": {"true"}},
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
	},
	{
		name:   "aws:PrincipalServiceName in Context does not grant a caller",
		src:    docCondKeys,
		stated: "This key is present in the request when the call is made by an AWS service principal. This key is not present in any other situation",
		resource: rpBucket("Allow", `"Principal":"*"`,
			`{"StringEquals":{"aws:PrincipalServiceName":"s3.amazonaws.com"}}`),
		caller:   rpPartner,
		identity: []string{rpAllowGet},
		ctx:      cfCtx{"aws:PrincipalServiceName": {"s3.amazonaws.com"}},
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:   "aws:PrincipalServiceNamesList in Context does not grant a caller",
		src:    docCondKeys,
		stated: "This key is present in the request when the call is made by an AWS service principal. This key is not present in any other situation",
		resource: rpBucket("Allow", `"Principal":"*"`,
			`{"ForAnyValue:StringEquals":{"aws:PrincipalServiceNamesList":"s3.amazonaws.com"}}`),
		caller:   rpPartner,
		identity: []string{rpAllowGet},
		ctx:      cfCtx{"aws:PrincipalServiceNamesList": {"s3.amazonaws.com"}},
		want:     policy.ImplicitDeny,
		reason:   policy.NoResourceAllow,
	},
	{
		name:     "aws:PrincipalServiceName in Context does not spare a caller from the CodeBuild-only Deny",
		src:      docNotPrincipal,
		stated:   "prevent all service principals, except those specified in the Condition element",
		resource: "deny-not-codebuild.json",
		caller:   rpDev,
		identity: []string{rpAllowGet},
		res:      "arn:aws:s3:::BUCKETNAME/key",
		ctx:      cfCtx{"aws:PrincipalServiceName": {"codebuild.amazonaws.com"}},
		want:     policy.ExplicitDeny,
		reason:   policy.ResourceDeny,
	},
}

func TestConformanceServiceCallerKeys(t *testing.T) { rpRun(t, spCallerKeyCases) }
