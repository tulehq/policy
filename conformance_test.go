package policy_test

// Conformance suite for tule.dev/policy, written from AWS documentation only.
//
// Every case names the AWS documentation page it comes from and the outcome
// that page states. Cases whose outcome AWS does not state outright are marked
// "ASSUMPTION:" with the reasoning. Example policies copied from AWS pages live
// in testdata/aws (placeholders such as {{111122223333}} replaced with values);
// malformed documents live in testdata/malformed.

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"tule.dev/policy"
)

// AWS documentation pages used as the oracle.
const (
	iamDocs         = "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
	docGrammar      = iamDocs + "reference_policies_grammar.html"
	docVersion      = iamDocs + "reference_policies_elements_version.html"
	docAction       = iamDocs + "reference_policies_elements_action.html"
	docNotAction    = iamDocs + "reference_policies_elements_notaction.html"
	docResource     = iamDocs + "reference_policies_elements_resource.html"
	docNotResource  = iamDocs + "reference_policies_elements_notresource.html"
	docPrincipal    = iamDocs + "reference_policies_elements_principal.html"
	docCondition    = iamDocs + "reference_policies_elements_condition.html"
	docOperators    = iamDocs + "reference_policies_elements_condition_operators.html"
	docMultiKeys    = iamDocs + "reference_policies_condition-logic-multiple-context-keys-or-values.html"
	docSetOps       = iamDocs + "reference_policies_condition-single-vs-multi-valued-context-keys.html"
	docVariables    = iamDocs + "reference_policies_variables.html"
	docCondKeys     = iamDocs + "reference_policies_condition-keys.html"
	docEvalBasics   = iamDocs + "reference_policies_evaluation-logic_policy-eval-basics.html"
	docEvalDenyAll  = iamDocs + "reference_policies_evaluation-logic_policy-eval-denyallow.html"
	docExDates      = iamDocs + "reference_policies_examples_aws-dates.html"
	docExDenyIP     = iamDocs + "reference_policies_examples_aws_deny-ip.html"
	docThirdParty   = iamDocs + "id_roles_common-scenarios_third-party.html"
	docS3Examples   = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-policies-s3.html"
	docSQSExamples  = "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-examples-of-iam-policies.html"
	docSMExamples   = "https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html"
	docLambdaExampl = "https://docs.aws.amazon.com/lambda/latest/dg/permissions-user-function.html"
	docW3CDatetime  = "http://www.w3.org/TR/NOTE-datetime"
)

const cfUser = "arn:aws:iam::111122223333:user/Bob"

// cfAllowAll is an identity policy allowing everything, used to observe
// whether a Deny-only example policy denies (ExplicitDeny) or not (Allow).
const cfAllowAll = `{"Version":"2012-10-17","Statement":{"Sid":"AllowAll","Effect":"Allow","Action":"*","Resource":"*"}}`

// cfTestdata holds the AWS example and malformed documents.
var cfTestdata = os.DirFS("testdata")

type cfCtx = map[string][]string

// cfCase is one request against a group's policies.
//
//nolint:govet // fieldalignment: field order reads as the table rows do.
type cfCase struct {
	name   string
	src    string // AWS page
	stated string // outcome as AWS states it
	action string
	res    string
	ctx    cfCtx
	want   any     // policy.Allow, policy.ExplicitDeny or policy.ImplicitDeny
	pol    *int    // expected Result.Policy, nil = not checked
	sid    *string // expected Result.Sid, nil = not checked
}

// cfGroup is a set of policies and the requests evaluated against them. A
// policy entry ending in ".json" names a file in testdata/aws; any other
// entry is the document itself.
//
//nolint:govet // fieldalignment: field order reads as the table rows do.
type cfGroup struct {
	name     string
	policies []string
	cases    []cfCase
}

func cfInt(i int) *int       { return &i }
func cfStr(s string) *string { return &s }

func cfLoad(t testing.TB, name string) *policy.Policy {
	t.Helper()
	b, err := fs.ReadFile(cfTestdata, path.Join("aws", name))
	if err != nil {
		t.Fatalf("read testdata %s: %v", name, err)
	}
	p, err := policy.Parse(b)
	if err != nil {
		t.Fatalf("Parse(testdata/aws/%s): %v", name, err)
	}
	return p
}

func cfParse(t testing.TB, doc string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse(%s): %v", doc, err)
	}
	return p
}

func cfPolicy(t testing.TB, entry string) *policy.Policy {
	t.Helper()
	if strings.HasSuffix(entry, ".json") {
		return cfLoad(t, entry)
	}
	return cfParse(t, entry)
}

func cfRunGroups(t *testing.T, groups []cfGroup) {
	t.Helper()
	for _, g := range groups {
		t.Run(g.name, func(t *testing.T) {
			pols := make([]*policy.Policy, 0, len(g.policies))
			for _, e := range g.policies {
				pols = append(pols, cfPolicy(t, e))
			}
			cfRun(t, pols, g.cases)
		})
	}
}

func cfRun(t *testing.T, pols []*policy.Policy, cases []cfCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := policy.Request{
				Action:    c.action,
				Resource:  c.res,
				Principal: cfUser,
				Context:   c.ctx,
			}
			r := policy.Evaluate(req, pols...)
			if any(r.Decision) != c.want {
				t.Errorf(
					"Decision = %v, want %v\n  request: %s on %s ctx=%v\n  source: %s\n  AWS states: %s",
					r.Decision,
					c.want,
					c.action,
					c.res,
					c.ctx,
					c.src,
					c.stated,
				)
			}
			if c.pol != nil && r.Policy != *c.pol {
				t.Errorf("Policy = %v, want %d (source: %s)", r.Policy, *c.pol, c.src)
			}
			if c.sid != nil && r.Sid != *c.sid {
				t.Errorf("Sid = %q, want %q (source: %s)", r.Sid, *c.sid, c.src)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Grammar

// cfGrammarGroups: each document must parse and allow its request.
var cfGrammarGroups = []cfGroup{
	// Source: docGrammar, "<statement_block> = "Statement" : [ <statement>, ... ]"
	// plus "If the element takes an array but only one value is included, the
	// brackets are optional". Stated: a single statement object is valid.
	{
		"statement as object",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`,
		},
		[]cfCase{{
			name: "allowed", src: docGrammar, stated: "a statement object is valid",
			action: "s3:GetObject", res: "arn:aws:s3:::b/k", want: policy.Allow,
		}},
	},
	{
		"statement as array",
		[]string{
			`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:PutObject","Resource":"*"},{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
		},
		[]cfCase{{
			name: "allowed", src: docGrammar, stated: "a statement array is valid",
			action: "s3:GetObject", res: "arn:aws:s3:::b/k", want: policy.Allow,
		}},
	},
	// Source: docGrammar conventions: `"Action": [<action_string>]` and
	// `"Action": <action_string>` are both valid; same for resource lists.
	{
		"action and resource single-element arrays",
		[]string{
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::b/*"]}]}`,
		},
		[]cfCase{{
			name: "allowed", src: docGrammar, stated: "brackets optional for one value",
			action: "s3:GetObject", res: "arn:aws:s3:::b/k", want: policy.Allow,
		}},
	},
	{
		"action and resource arrays",
		[]string{
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["sqs:SendMessage","s3:GetObject"],"Resource":["arn:aws:s3:::a/*","arn:aws:s3:::b/*"]}]}`,
		},
		[]cfCase{{
			name: "allowed", src: docGrammar, stated: "arrays of actions and resources",
			action: "s3:GetObject", res: "arn:aws:s3:::b/k", want: policy.Allow,
		}},
	},
	// Source: docGrammar, <condition_value_list> is an array; brackets optional
	// for one value (conventions section).
	{
		"condition value single",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:username":"john"}}}}`,
		},
		[]cfCase{
			{
				name:   "allowed",
				src:    docGrammar,
				stated: "brackets optional for one value",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/k",
				ctx:    cfCtx{"aws:username": {"john"}},
				want:   policy.Allow,
			},
		},
	},
	{
		"condition value array",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:username":["john"]}}}}`,
		},
		[]cfCase{
			{
				name:   "allowed",
				src:    docGrammar,
				stated: "<condition_value_list> is an array",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/k",
				ctx:    cfCtx{"aws:username": {"john"}},
				want:   policy.Allow,
			},
		},
	},
	// Source: docGrammar, "Quotation marks are optional for numeric and Boolean values."
	{
		"unquoted boolean condition value",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":true}}}}`,
		},
		[]cfCase{
			{
				name:   "allowed",
				src:    docGrammar,
				stated: "quotation marks optional for Boolean values",
				action: "s3:ListBucket",
				res:    "arn:aws:s3:::b",
				ctx:    cfCtx{"aws:SecureTransport": {"true"}},
				want:   policy.Allow,
			},
		},
	},
	{
		"unquoted numeric condition value",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*","Condition":{"NumericLessThanEquals":{"s3:max-keys":10}}}}`,
		},
		[]cfCase{
			{
				name:   "allowed",
				src:    docGrammar,
				stated: "quotation marks optional for numeric values",
				action: "s3:ListBucket",
				res:    "arn:aws:s3:::b",
				ctx:    cfCtx{"s3:max-keys": {"10"}},
				want:   policy.Allow,
			},
		},
	},
	// Source: docGrammar, "<version_block?>" is optional; docVersion describes
	// policies without it. Stated: a policy without Version is still a policy.
	{"missing Version", []string{
		`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`,
	}, []cfCase{{
		name: "allowed", src: docGrammar, stated: "<version_block?> is optional",
		action: "s3:GetObject", res: "arn:aws:s3:::b/k", want: policy.Allow,
	}}},
	// Source: docGrammar, Version is "2008-10-17" | "2012-10-17".
	{
		"Version 2008-10-17",
		[]string{
			`{"Version":"2008-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`,
		},
		[]cfCase{{
			name: "allowed", src: docGrammar, stated: `"Version" : ("2008-10-17" | "2012-10-17")`,
			action: "s3:GetObject", res: "arn:aws:s3:::b/k", want: policy.Allow,
		}},
	},
	// Source: docGrammar, "Blocks can appear in any order"; Id example "Admin_Policy".
	{
		"Id and any block order",
		[]string{
			`{"Statement":[{"Resource":"*","Action":"s3:GetObject","Effect":"Allow","Sid":"1"}],"Id":"Admin_Policy","Version":"2012-10-17"}`,
		},
		[]cfCase{{
			name: "allowed", src: docGrammar, stated: "Blocks can appear in any order",
			action: "s3:GetObject", res: "arn:aws:s3:::b/k", want: policy.Allow,
		}},
	},
}

// Source: docGrammar, "<principal_block> = ("Principal" | "NotPrincipal")";
// trust policies carry Principal and no Resource (docPrincipal examples).
var cfTrustForms = []string{
	`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`,
	`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"sts:AssumeRole"}}`,
	`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:root","999999999999"]},"Action":"sts:AssumeRole"}}`,
	`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":["ecs.amazonaws.com","elasticloadbalancing.amazonaws.com"]},"Action":"sts:AssumeRole"}}`,
	`{"Version":"2012-10-17","Statement":{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::123456789012:user/Bob"},"Action":"sts:AssumeRole"}}`,
}

func TestConformanceGrammar(t *testing.T) {
	cfRunGroups(t, cfGrammarGroups)
	t.Run("trust policy forms parse", func(t *testing.T) {
		for _, doc := range cfTrustForms {
			if _, err := policy.Parse([]byte(doc)); err != nil {
				t.Errorf("Parse(%s): %v", doc, err)
			}
		}
	})
	t.Run("every AWS example in testdata parses", func(t *testing.T) {
		files, err := fs.Glob(cfTestdata, "aws/*.json")
		if err != nil || len(files) == 0 {
			t.Fatalf("no testdata/aws files (%v)", err)
		}
		for _, f := range files {
			cfLoad(t, path.Base(f))
		}
	})
}

// cfMalformed gives, for each file in testdata/malformed, the rule it breaks.
var cfMalformed = map[string]string{
	"invalid-json":             docGrammar + ": IAM identifies JSON syntax errors",
	"empty":                    docGrammar + ": policy = { ... <statement_block> }",
	"null":                     docGrammar + ": policy = { ... }",
	"top-level-array":          docGrammar + ": policy = { ... } (an object)",
	"trailing-garbage":         docGrammar + ": a policy is one JSON object (RFC 7159 text)",
	"no-statement":             docGrammar + ": <statement_block> is not optional",
	"statement-string":         docGrammar + ": Statement is a <statement> or an array of them",
	"effect-missing":           docGrammar + ": <effect_block> is required in <statement>",
	"effect-invalid":           docGrammar + `: "Effect" : ("Allow" | "Deny")`,
	"action-missing":           docAction + ": Statements must include either an Action or NotAction element",
	"action-and-notaction":     docGrammar + `: <action_block> = ("Action" | "NotAction")`,
	"action-number":            docGrammar + ": action_string is a string",
	"resource-missing":         docResource + ": Statements must include either a Resource or a NotResource element (identity statement, no Principal)",
	"resource-and-notresource": docGrammar + `: <resource_block> = ("Resource" | "NotResource")`,
	"version-invalid":          docGrammar + `: "Version" : ("2008-10-17" | "2012-10-17")`,
	"duplicate-effect":         docGrammar + ": Individual elements must not contain multiple instances of the same key",
	"condition-not-object":     docGrammar + `: "Condition" : { <condition_map> }`,
	"condition-key-not-object": docGrammar + ": <condition_type_string> : { <condition_key_string> : <condition_value_list> }",
}

// Malformed documents must be refused with a *policy.ParseError.
func TestConformanceMalformed(t *testing.T) {
	files, err := fs.Glob(cfTestdata, "malformed/*.json")
	if err != nil || len(files) != len(cfMalformed) {
		t.Fatalf(
			"testdata/malformed has %d files, table has %d (%v)",
			len(files),
			len(cfMalformed),
			err,
		)
	}
	for _, f := range files {
		name := strings.TrimSuffix(path.Base(f), ".json")
		t.Run(name, func(t *testing.T) {
			src, ok := cfMalformed[name]
			if !ok {
				t.Fatalf("no source recorded for %s", name)
			}
			b, err := fs.ReadFile(cfTestdata, f)
			if err != nil {
				t.Fatal(err)
			}
			p, err := policy.Parse(b)
			if err == nil {
				t.Fatalf("Parse accepted malformed document (%s)\n  doc: %s", src, b)
			}
			if p != nil {
				t.Errorf("Parse returned a non-nil *Policy with an error")
			}
			var pe *policy.ParseError
			if !errors.As(err, &pe) {
				t.Errorf("error %T (%v) is not a *policy.ParseError", err, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Precedence

var cfPrecedenceGroups = []cfGroup{
	// Source: docEvalBasics, Carlos example (identity policy only; the bucket
	// policy is resource-based and outside this library).
	// Stated: saving to amzn-s3-demo-bucket-carlossalazar-logs is denied by the
	// explicit deny DenyS3Logs; saving to amzn-s3-demo-bucket-carlossalazar is
	// allowed; AllowS3ListRead lets him list all buckets.
	{
		"carlos",
		[]string{"carlos-identity.json"},
		[]cfCase{
			{
				name:   "logs bucket explicit deny",
				src:    docEvalBasics,
				stated: "Carlos is denied access",
				action: "s3:PutObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar-logs/report.txt",
				want:   policy.ExplicitDeny,
				pol:    cfInt(0),
				sid:    cfStr("DenyS3Logs"),
			},
			{
				name:   "own bucket allowed",
				src:    docEvalBasics,
				stated: "AWS allows the request",
				action: "s3:PutObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar/report.txt",
				want:   policy.Allow,
				pol:    cfInt(0),
				sid:    cfStr("AllowS3Self"),
			},
			{
				name:   "list all buckets",
				src:    docEvalBasics,
				stated: "allows Carlos to view a list of all of the buckets",
				action: "s3:ListAllMyBuckets",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket-other",
				want:   policy.Allow,
				pol:    cfInt(0),
				sid:    cfStr("AllowS3ListRead"),
			},
		},
	},
	// Source: docExDenyIP. Stated: "When other policies allow actions,
	// principals can make requests from within the IP address range ... When a
	// principal makes a request from outside the IP range, the request is denied."
	// Source: docEvalDenyAll: "If the enforcement code finds even one explicit
	// deny that applies, the enforcement code returns a final decision of Deny."
	// ASSUMPTION: a statement without Sid reports Sid "".
	{
		"explicit deny across policies",
		[]string{cfAllowAll, "deny-ip.json"},
		[]cfCase{
			{
				name:   "outside range denied",
				src:    docExDenyIP,
				stated: "request from outside the IP range is denied",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/k",
				ctx:    cfCtx{"aws:SourceIp": {"198.51.100.1"}},
				want:   policy.ExplicitDeny,
				pol:    cfInt(1),
				sid:    cfStr(""),
			},
			{
				name:   "inside range allowed",
				src:    docExDenyIP,
				stated: "principals can make requests from within the range",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/k",
				ctx:    cfCtx{"aws:SourceIp": {"203.0.113.5"}},
				want:   policy.Allow,
				pol:    cfInt(0),
				sid:    cfStr("AllowAll"),
			},
		},
	},
	// Order of policies does not matter for an explicit deny.
	{
		"explicit deny listed first",
		[]string{"deny-ip.json", cfAllowAll},
		[]cfCase{
			{
				name:   "deny first",
				src:    docEvalDenyAll,
				stated: "one explicit deny that applies returns Deny",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/k",
				ctx:    cfCtx{"aws:SourceIp": {"192.0.3.1"}},
				want:   policy.ExplicitDeny,
				pol:    cfInt(0),
			},
		},
	},
	// Source: docEvalDenyAll: "If there are no identity-based policies or no
	// statements in identity-based policies that allow the requested action,
	// then the request is implicitly denied".
	{
		"implicit deny with no policies",
		nil,
		[]cfCase{
			{
				name:   "no policies",
				src:    docEvalDenyAll,
				stated: "no identity-based policies: implicitly denied",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/k",
				want:   policy.ImplicitDeny,
				pol:    cfInt(-1),
			},
		},
	},
	{"implicit deny with no allowing statement", []string{"sqs-shared-queue.json"}, []cfCase{
		{
			name: "no statement allows", src: docEvalDenyAll, stated: "implicitly denied",
			action: "sqs:DeleteQueue", res: "arn:aws:sqs:us-east-1:123456789012:MyCompanyQueue",
			want: policy.ImplicitDeny, pol: cfInt(-1),
		},
	}},
	// Source: docS3Examples, "Restricting bucket creation to one Region" with
	// the explicit deny. Stated: the user can create buckets only in sa-east-1;
	// "a create bucket request is denied if the location constraint is not sa-east-1".
	{
		"s3 region guard",
		[]string{"s3-createbucket-region.json", cfAllowAll},
		[]cfCase{
			{
				name:   "sa-east-1 allowed",
				src:    docS3Examples,
				stated: "permission to create a bucket in sa-east-1",
				action: "s3:CreateBucket",
				res:    "arn:aws:s3:::examplebucket",
				ctx:    cfCtx{"s3:LocationConstraint": {"sa-east-1"}},
				want:   policy.Allow,
			},
			{
				name:   "other region denied despite other allow",
				src:    docS3Examples,
				stated: "explicit deny ... no matter what other permission the user gets",
				action: "s3:CreateBucket",
				res:    "arn:aws:s3:::examplebucket",
				ctx:    cfCtx{"s3:LocationConstraint": {"us-west-2"}},
				want:   policy.ExplicitDeny,
				pol:    cfInt(0),
				sid:    cfStr("statement2"),
			},
		},
	},
}

func TestConformancePrecedence(t *testing.T) { cfRunGroups(t, cfPrecedenceGroups) }

// ---------------------------------------------------------------------------
// Action matching

var cfActionGroups = []cfGroup{
	// Source: docAction: "iam:*AccessKey*" applies to "CreateAccessKey,
	// DeleteAccessKey, ListAccessKeys, and UpdateAccessKey".
	{
		"star in action name",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:*AccessKey*","Resource":"*"}}`,
		},
		[]cfCase{
			{
				name:   "CreateAccessKey",
				src:    docAction,
				stated: "matched by iam:*AccessKey*",
				action: "iam:CreateAccessKey",
				res:    "arn:aws:iam::111122223333:user/Bob",
				want:   policy.Allow,
			},
			{
				name:   "DeleteAccessKey",
				src:    docAction,
				stated: "matched by iam:*AccessKey*",
				action: "iam:DeleteAccessKey",
				res:    "arn:aws:iam::111122223333:user/Bob",
				want:   policy.Allow,
			},
			{
				name:   "ListAccessKeys",
				src:    docAction,
				stated: "matched by iam:*AccessKey*",
				action: "iam:ListAccessKeys",
				res:    "arn:aws:iam::111122223333:user/Bob",
				want:   policy.Allow,
			},
			{
				name:   "UpdateAccessKey",
				src:    docAction,
				stated: "matched by iam:*AccessKey*",
				action: "iam:UpdateAccessKey",
				res:    "arn:aws:iam::111122223333:user/Bob",
				want:   policy.Allow,
			},
			// ASSUMPTION (obvious from the pattern): CreateUser contains no "AccessKey".
			{
				name:   "CreateUser not matched",
				src:    docAction,
				stated: "pattern requires AccessKey",
				action: "iam:CreateUser",
				res:    "arn:aws:iam::111122223333:user/Bob",
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docAction: "The prefix and the action name are case insensitive.
	// For example, iam:ListAccessKeys is the same as IAM:listaccesskeys."
	{
		"case insensitive request",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:ListAccessKeys","Resource":"*"}}`,
		},
		[]cfCase{
			{
				name:   "request upper",
				src:    docAction,
				stated: "iam:ListAccessKeys is the same as IAM:listaccesskeys",
				action: "IAM:listaccesskeys",
				res:    "*",
				want:   policy.Allow,
			},
		},
	},
	{
		"case insensitive policy",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"IAM:listaccesskeys","Resource":"*"}}`,
		},
		[]cfCase{
			{
				name:   "policy upper",
				src:    docAction,
				stated: "iam:ListAccessKeys is the same as IAM:listaccesskeys",
				action: "iam:ListAccessKeys",
				res:    "*",
				want:   policy.Allow,
			},
		},
	},
	{
		"case insensitive with wildcard",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"S3:Get*","Resource":"*"}}`,
		},
		[]cfCase{
			{
				name:   "wildcard and case",
				src:    docAction,
				stated: "prefix and name case insensitive; * wildcard",
				action: "s3:getobject",
				res:    "arn:aws:s3:::b/k",
				want:   policy.Allow,
			},
		},
	},
	// Source: docAction: "single-character match wildcards (?)"; docOperators
	// describes ? as matching a single character.
	{
		"question mark",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:?etObject","Resource":"*"}}`,
		},
		[]cfCase{
			{
				name:   "GetObject",
				src:    docAction,
				stated: "? matches one character",
				action: "s3:GetObject",
				res:    "*",
				want:   policy.Allow,
			},
			{
				name:   "two characters",
				src:    docAction,
				stated: "? matches exactly one character",
				action: "s3:GGetObject",
				res:    "*",
				want:   policy.ImplicitDeny,
			},
			{
				name:   "zero characters",
				src:    docAction,
				stated: "? matches exactly one character",
				action: "s3:etObject",
				res:    "*",
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docGrammar action_string examples "*", "s3:Get*", "s3:List*";
	// docAction: "s3:*" applies to all S3 actions.
	{"star alone", []string{
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
	}, []cfCase{{
		name: "star matches any service", src: docGrammar, stated: `"Action":"*"`,
		action: "sqs:SendMessage", res: "*", want: policy.Allow,
	}}},
	{
		"Get* and List*",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":"*"}}`,
		},
		[]cfCase{
			{
				name:   "Get*",
				src:    docGrammar,
				stated: "s3:Get*",
				action: "s3:GetObject",
				res:    "*",
				want:   policy.Allow,
			},
			{
				name:   "List*",
				src:    docGrammar,
				stated: "s3:List*",
				action: "s3:ListBucket",
				res:    "*",
				want:   policy.Allow,
			},
			{
				name:   "Put not listed",
				src:    docGrammar,
				stated: "only Get* and List*",
				action: "s3:PutObject",
				res:    "*",
				want:   policy.ImplicitDeny,
			},
		},
	},
	{
		"service star stays in service",
		[]string{"sqs-alice-queue.json"},
		[]cfCase{
			{
				name:   "sqs:* does not cross services",
				src:    docSQSExamples,
				stated: "sqs:* grants all Amazon SQS actions",
				action: "sns:Publish",
				res:    "arn:aws:sqs:us-east-1:123456789012:alice_queue_1",
				want:   policy.ImplicitDeny,
			},
		},
	},
	{
		"secrets manager List*",
		[]string{"secrets-metadata.json"},
		[]cfCase{
			{
				name:   "List* ListSecrets",
				src:    docSMExamples,
				stated: "grants DescribeSecret and permissions beginning with List",
				action: "secretsmanager:ListSecrets",
				res:    "*",
				want:   policy.Allow,
			},
			{
				name:   "List* ListSecretVersionIds",
				src:    docSMExamples,
				stated: "ListSecrets and ListSecretVersionIds",
				action: "secretsmanager:ListSecretVersionIds",
				res:    "*",
				want:   policy.Allow,
			},
			{
				name:   "GetSecretValue not granted",
				src:    docSMExamples,
				stated: "only DescribeSecret and List*",
				action: "secretsmanager:GetSecretValue",
				res:    "*",
				want:   policy.ImplicitDeny,
			},
		},
	},
}

func TestConformanceActions(t *testing.T) { cfRunGroups(t, cfActionGroups) }

// ---------------------------------------------------------------------------
// NotAction and NotResource

var cfNotActionGroups = []cfGroup{
	// Source: docNotAction: "allows users to access every action in every AWS
	// service except for IAM."
	{
		"allow NotAction iam:*",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}}`,
		},
		[]cfCase{
			{
				name:   "s3 allowed",
				src:    docNotAction,
				stated: "every action in every service except IAM",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/k",
				want:   policy.Allow,
			},
			{
				name:   "ec2 allowed",
				src:    docNotAction,
				stated: "every action in every service except IAM",
				action: "ec2:RunInstances",
				res:    "*",
				want:   policy.Allow,
			},
			{
				name:   "iam not allowed",
				src:    docNotAction,
				stated: "except for IAM",
				action: "iam:CreateUser",
				res:    "arn:aws:iam::111122223333:user/x",
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docNotAction: allows "all of the Amazon S3 actions that can be
	// performed on any S3 resource except for deleting a bucket. This policy
	// also does not allow actions in other services".
	{
		"allow NotAction scoped by Resource",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","NotAction":"s3:DeleteBucket","Resource":"arn:aws:s3:::*"}}`,
		},
		[]cfCase{
			{
				name:   "GetObject allowed",
				src:    docNotAction,
				stated: "all S3 actions except DeleteBucket",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/k",
				want:   policy.Allow,
			},
			{
				name:   "DeleteBucket not allowed",
				src:    docNotAction,
				stated: "except for deleting a bucket",
				action: "s3:DeleteBucket",
				res:    "arn:aws:s3:::b",
				want:   policy.ImplicitDeny,
			},
			{
				name:   "other service not allowed",
				src:    docNotAction,
				stated: "does not allow actions in other services",
				action: "ec2:RunInstances",
				res:    "arn:aws:ec2:us-east-1:111122223333:instance/i-1",
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docNotAction, DenyAllUsersNotUsingMFA: "denies access to non-IAM
	// actions if the user is not signed in using MFA. If the user is signed in
	// with MFA, then the Condition test fails and the final Deny statement has
	// no effect ... it would not grant the user access to any actions".
	// Source: docCondKeys aws:MultiFactorAuthPresent: BoolIfExists false
	// "also denies long-term credential requests" (key absent).
	{
		"deny NotAction with MFA condition",
		[]string{"notaction-mfa-deny.json", cfAllowAll},
		[]cfCase{
			{
				name:   "no MFA non-IAM denied",
				src:    docNotAction,
				stated: "denies non-IAM actions without MFA",
				action: "ec2:RunInstances",
				res:    "*",
				ctx:    cfCtx{"aws:MultiFactorAuthPresent": {"false"}},
				want:   policy.ExplicitDeny,
				pol:    cfInt(0),
				sid:    cfStr("DenyAllUsersNotUsingMFA"),
			},
			{
				name:   "long-term creds non-IAM denied",
				src:    docCondKeys,
				stated: "BoolIfExists false also denies long-term credential requests",
				action: "ec2:RunInstances",
				res:    "*",
				want:   policy.ExplicitDeny,
			},
			{
				name:   "MFA present not denied",
				src:    docNotAction,
				stated: "with MFA the Deny has no effect",
				action: "ec2:RunInstances",
				res:    "*",
				ctx:    cfCtx{"aws:MultiFactorAuthPresent": {"true"}},
				want:   policy.Allow,
				pol:    cfInt(1),
			},
			{
				name:   "IAM action not denied",
				src:    docNotAction,
				stated: "only denies all other actions except IAM",
				action: "iam:ChangePassword",
				res:    "*",
				ctx:    cfCtx{"aws:MultiFactorAuthPresent": {"false"}},
				want:   policy.Allow,
				pol:    cfInt(1),
			},
		},
	},
	{
		"deny NotAction alone",
		[]string{"notaction-mfa-deny.json"},
		[]cfCase{
			{
				name:   "deny alone grants nothing",
				src:    docNotAction,
				stated: "would not grant the user access to any actions",
				action: "iam:ChangePassword",
				res:    "*",
				ctx:    cfCtx{"aws:MultiFactorAuthPresent": {"true"}},
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docLambdaExampl, DevelopFunctions: "Use any Lambda action that
	// operates on functions prefixed with intern-, except AddPermission and
	// PutFunctionConcurrency."
	{
		"lambda intern policy",
		[]string{"lambda-intern.json"},
		[]cfCase{
			{
				name:   "update intern function",
				src:    docLambdaExampl,
				stated: "any Lambda action on intern- functions",
				action: "lambda:UpdateFunctionCode",
				res:    "arn:aws:lambda:us-east-1:111122223333:function:intern-foo",
				want:   policy.Allow,
				sid:    cfStr("DevelopFunctions"),
			},
			{
				name:   "AddPermission excluded",
				src:    docLambdaExampl,
				stated: "except AddPermission",
				action: "lambda:AddPermission",
				res:    "arn:aws:lambda:us-east-1:111122223333:function:intern-foo",
				want:   policy.ImplicitDeny,
			},
			{
				name:   "PutFunctionConcurrency excluded",
				src:    docLambdaExampl,
				stated: "except PutFunctionConcurrency",
				action: "lambda:PutFunctionConcurrency",
				res:    "arn:aws:lambda:us-east-1:111122223333:function:intern-foo",
				want:   policy.ImplicitDeny,
			},
			{
				name:   "non-intern function",
				src:    docLambdaExampl,
				stated: "only functions prefixed with intern-",
				action: "lambda:UpdateFunctionCode",
				res:    "arn:aws:lambda:us-east-1:111122223333:function:prod-foo",
				want:   policy.ImplicitDeny,
			},
			{
				name:   "read-only on any function",
				src:    docLambdaExampl,
				stated: "ReadOnlyPermissions on Resource *",
				action: "lambda:GetFunction",
				res:    "arn:aws:lambda:us-east-1:111122223333:function:prod-foo",
				want:   policy.Allow,
				sid:    cfStr("ReadOnlyPermissions"),
			},
			// Source: docResource: "If the * wildcard is the last character of a
			// resource ARN segment, it can expand to match beyond the colon boundaries."
			{
				name:   "qualified intern function",
				src:    docResource,
				stated: "trailing * expands beyond colon boundaries",
				action: "lambda:InvokeFunction",
				res:    "arn:aws:lambda:us-east-1:111122223333:function:intern-foo:PROD",
				want:   policy.Allow,
				sid:    cfStr("DevelopFunctions"),
			},
			{
				name:   "event source mapping for intern",
				src:    docLambdaExampl,
				stated: "manage event source mappings on intern- functions",
				action: "lambda:CreateEventSourceMapping",
				res:    "*",
				ctx: cfCtx{
					"lambda:FunctionArn": {
						"arn:aws:lambda:us-east-1:111122223333:function:intern-foo",
					},
				},
				want: policy.Allow,
				sid:  cfStr("DevelopEventSourceMappings"),
			},
			{
				name:   "event source mapping for other",
				src:    docLambdaExampl,
				stated: "restricted by function with a condition",
				action: "lambda:CreateEventSourceMapping",
				res:    "*",
				ctx: cfCtx{
					"lambda:FunctionArn": {
						"arn:aws:lambda:us-east-1:111122223333:function:prod-foo",
					},
				},
				want: policy.ImplicitDeny,
			},
			{
				name:   "pass only the intern role",
				src:    docLambdaExampl,
				stated: "pass only a role named intern-lambda-execution-role",
				action: "iam:PassRole",
				res:    "arn:aws:iam::111122223333:role/intern-lambda-execution-role",
				want:   policy.Allow,
			},
			{
				name:   "pass another role",
				src:    docLambdaExampl,
				stated: "only intern-lambda-execution-role",
				action: "iam:PassRole",
				res:    "arn:aws:iam::111122223333:role/admin",
				want:   policy.ImplicitDeny,
			},
			{
				name:   "logs for intern",
				src:    docLambdaExampl,
				stated: "view logs for intern- functions",
				action: "logs:GetLogEvents",
				res:    "arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/intern-foo",
				want:   policy.Allow,
			},
		},
	},
	// Source: docNotResource HRPayroll: "explicitly denies access to all Amazon
	// S3 resources other than the listed resources ... does not grant the user
	// access to any resources."
	{
		"deny NotResource",
		[]string{"notresource-hrpayroll.json", cfAllowAll},
		[]cfCase{
			{
				name:   "other bucket denied",
				src:    docNotResource,
				stated: "denies access to all S3 resources other than listed",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::OtherBucket/a.txt",
				want:   policy.ExplicitDeny,
				pol:    cfInt(0),
			},
			{
				name:   "payroll object allowed",
				src:    docNotResource,
				stated: "listed resources are the only ones not limited",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::HRBucket/Payroll/jan.csv",
				want:   policy.Allow,
				pol:    cfInt(1),
			},
			{
				name:   "payroll folder allowed",
				src:    docNotResource,
				stated: "listed resources are the only ones not limited",
				action: "s3:ListBucket",
				res:    "arn:aws:s3:::HRBucket/Payroll",
				want:   policy.Allow,
			},
		},
	},
	{
		"deny NotResource alone",
		[]string{"notresource-hrpayroll.json"},
		[]cfCase{
			{
				name:   "deny alone grants nothing",
				src:    docNotResource,
				stated: "does not grant the user access to any resources",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::HRBucket/Payroll/jan.csv",
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docNotResource: Allow + "Action":"*" + NotResource HRBucket
	// "allows all actions in AWS on all resources except the HRBucket S3 bucket.
	// This would even allow the user to add a policy to themselves".
	{
		"allow NotResource pitfall",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","NotResource":"arn:aws:s3:::HRBucket"}}`,
		},
		[]cfCase{
			{
				name:   "self-grant allowed",
				src:    docNotResource,
				stated: "would even allow the user to add a policy to themselves",
				action: "iam:PutUserPolicy",
				res:    "arn:aws:iam::111122223333:user/Bob",
				want:   policy.Allow,
			},
			{
				name:   "HRBucket excluded",
				src:    docNotResource,
				stated: "all resources except the HRBucket bucket",
				action: "s3:ListBucket",
				res:    "arn:aws:s3:::HRBucket",
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docS3Examples "Allowing a partner to drop files": PutObject into
	// uploads/anycompany/*, plus an explicit deny "to any Amazon S3 actions
	// except PutObject on any Amazon S3 resource" outside that folder, "to
	// prevent the AnyCompany group from doing anything else with the bucket".
	{
		"s3 partner drop",
		[]string{"s3-partner-drop.json"},
		[]cfCase{
			{
				name:   "put into folder",
				src:    docS3Examples,
				stated: "PutObject access to uploads/anycompany",
				action: "s3:PutObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket1/uploads/anycompany/a.csv",
				want:   policy.Allow,
				pol:    cfInt(0),
			},
			{
				name:   "put elsewhere denied",
				src:    docS3Examples,
				stated: "explicitly denies S3 actions outside the folder",
				action: "s3:PutObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket1/uploads/other/a.csv",
				want:   policy.ExplicitDeny,
				pol:    cfInt(0),
			},
			{
				name:   "other bucket denied",
				src:    docS3Examples,
				stated: "explicitly denies S3 actions on any other S3 resource",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::another-bucket/a.csv",
				want:   policy.ExplicitDeny,
			},
			{
				name:   "get in folder not allowed",
				src:    docS3Examples,
				stated: "prevent the group from doing anything else",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket1/uploads/anycompany/a.csv",
				want:   policy.ImplicitDeny,
				pol:    cfInt(-1),
			},
		},
	},
}

func TestConformanceNotActionNotResource(t *testing.T) { cfRunGroups(t, cfNotActionGroups) }

// ---------------------------------------------------------------------------
// Resource ARNs

// Source: docResource, "arn:aws:s3:::amzn-s3-demo-bucket/*/test/*" applies
// to the eight listed objects and does not match the three listed after.
var (
	cfS3KeysMatch = []string{
		"amzn-s3-demo-bucket/1/test/object.jpg",
		"amzn-s3-demo-bucket/1/2/test/object.jpg",
		"amzn-s3-demo-bucket/1/2/test/3/object.jpg",
		"amzn-s3-demo-bucket/1/2/3/test/4/object.jpg",
		"amzn-s3-demo-bucket/1///test///object.jpg",
		"amzn-s3-demo-bucket/1/test/.jpg",
		"amzn-s3-demo-bucket//test/object.jpg",
		"amzn-s3-demo-bucket/1/test/",
	}
	cfS3KeysNoMatch = []string{
		"amzn-s3-demo-bucket/1-test/object.jpg",
		"amzn-s3-demo-bucket/test/object.jpg",
		"amzn-s3-demo-bucket/1/2/test.jpg",
	}
)

func cfS3KeyCases() []cfCase {
	cases := make([]cfCase, 0, len(cfS3KeysMatch)+len(cfS3KeysNoMatch))
	for _, k := range cfS3KeysMatch {
		cases = append(cases, cfCase{
			name: "match " + k, src: docResource, stated: "the wildcards apply to this object",
			action: "s3:GetObject", res: "arn:aws:s3:::" + k, want: policy.Allow,
		})
	}
	for _, k := range cfS3KeysNoMatch {
		cases = append(cases, cfCase{
			name: "no match " + k, src: docResource, stated: "The ARN would not match",
			action: "s3:GetObject", res: "arn:aws:s3:::" + k, want: policy.ImplicitDeny,
		})
	}
	return cases
}

var cfResourceGroups = []cfGroup{
	{
		"s3 key paths",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::amzn-s3-demo-bucket/*/test/*"}}`,
		},
		cfS3KeyCases(),
	},
	// Source: docResource: "all IAM users whose path is /accounting";
	// "In the Resource element, the IAM user name is case sensitive."
	{
		"iam paths and case",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:GetUser","Resource":["arn:aws:iam::111122223333:user/accounting/*","arn:aws:iam::111122223333:user/Bob"]}}`,
		},
		[]cfCase{
			{
				name:   "accounting user",
				src:    docResource,
				stated: "all IAM users whose path is /accounting",
				action: "iam:GetUser",
				res:    "arn:aws:iam::111122223333:user/accounting/Jane",
				want:   policy.Allow,
			},
			{
				name:   "user outside path",
				src:    docResource,
				stated: "only users under /accounting",
				action: "iam:GetUser",
				res:    "arn:aws:iam::111122223333:user/Jane",
				want:   policy.ImplicitDeny,
			},
			{
				name:   "Bob",
				src:    docResource,
				stated: "refers to the IAM user named Bob",
				action: "iam:GetUser",
				res:    "arn:aws:iam::111122223333:user/Bob",
				want:   policy.Allow,
			},
			{
				name:   "bob lowercase",
				src:    docResource,
				stated: "the IAM user name is case sensitive",
				action: "iam:GetUser",
				res:    "arn:aws:iam::111122223333:user/bob",
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docGrammar resource_string: "specifying arn:aws:sqs is equivalent
	// to arn:aws:sqs:*:*:*, which grants access to all Amazon SQS resources
	// across all regions and accounts" (identity-based policies).
	{
		"incomplete ARN",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"arn:aws:sqs"}}`,
		},
		[]cfCase{
			{
				name:   "any queue",
				src:    docGrammar,
				stated: "arn:aws:sqs is equivalent to arn:aws:sqs:*:*:*",
				action: "sqs:SendMessage",
				res:    "arn:aws:sqs:eu-west-1:999999999999:q1",
				want:   policy.Allow,
			},
		},
	},
	// Source: docSQSExamples: Bob may use "all Amazon SQS actions, but only with
	// queues whose names are prefixed with the literal string alice_queue_";
	// MyCompanyQueue "belongs to the specified AWS account".
	{
		"sqs alice queue",
		[]string{"sqs-alice-queue.json"},
		[]cfCase{
			{
				name:   "alice queue any region",
				src:    docSQSExamples,
				stated: "queues prefixed with alice_queue_",
				action: "sqs:CreateQueue",
				res:    "arn:aws:sqs:us-east-2:123456789012:alice_queue_orders",
				want:   policy.Allow,
			},
			{
				name:   "other prefix",
				src:    docSQSExamples,
				stated: "only queues prefixed with alice_queue_",
				action: "sqs:SendMessage",
				res:    "arn:aws:sqs:us-east-2:123456789012:bob_queue_orders",
				want:   policy.ImplicitDeny,
			},
			{
				name:   "other account",
				src:    docSQSExamples,
				stated: "account 123456789012 only",
				action: "sqs:SendMessage",
				res:    "arn:aws:sqs:us-east-2:999999999999:alice_queue_orders",
				want:   policy.ImplicitDeny,
			},
		},
	},
	{
		"sqs shared queue",
		[]string{"sqs-shared-queue.json"},
		[]cfCase{
			{
				name:   "shared queue send",
				src:    docSQSExamples,
				stated: "SendMessage on MyCompanyQueue",
				action: "sqs:SendMessage",
				res:    "arn:aws:sqs:us-east-1:123456789012:MyCompanyQueue",
				want:   policy.Allow,
			},
			{
				name:   "shared queue receive",
				src:    docSQSExamples,
				stated: "only SendMessage",
				action: "sqs:ReceiveMessage",
				res:    "arn:aws:sqs:us-east-1:123456789012:MyCompanyQueue",
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docSMExamples "Match secret name": ?????? matches the six random
	// characters; "another_secret_name-*" would also match
	// "another_secret_name-<anything-here>a1b2c3" (?????? does not).
	{
		"secrets manager names",
		[]string{"secrets-match-name.json"},
		[]cfCase{
			{
				name:   "six random chars",
				src:    docSMExamples,
				stated: "?????? matches the six random characters",
				action: "secretsmanager:GetSecretValue",
				res:    "arn:aws:secretsmanager:us-east-1:123456789012:secret:another_secret_name-x9Y8z7",
				want:   policy.Allow,
			},
			{
				name:   "extra chars before suffix",
				src:    docSMExamples,
				stated: "only * would match <anything-here>a1b2c3",
				action: "secretsmanager:GetSecretValue",
				res:    "arn:aws:secretsmanager:us-east-1:123456789012:secret:another_secret_name-extra-a1b2c3",
				want:   policy.ImplicitDeny,
			},
			{
				name:   "exact secret",
				src:    docSMExamples,
				stated: "grants permissions for a secret by name",
				action: "secretsmanager:DescribeSecret",
				res:    "arn:aws:secretsmanager:us-east-1:123456789012:secret:a_specific_secret_name-a1b2c3",
				want:   policy.Allow,
			},
			{
				name:   "exact secret other suffix",
				src:    docSMExamples,
				stated: "exact ARN only",
				action: "secretsmanager:DescribeSecret",
				res:    "arn:aws:secretsmanager:us-east-1:123456789012:secret:a_specific_secret_name-zzzzzz",
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docSMExamples "Access all secrets in a path": names beginning with TestEnv/.
	{
		"secrets manager path",
		[]string{"secrets-testenv.json"},
		[]cfCase{
			{
				name:   "TestEnv path",
				src:    docSMExamples,
				stated: "all secrets with a name beginning with TestEnv/",
				action: "secretsmanager:GetSecretValue",
				res:    "arn:aws:secretsmanager:us-east-1:123456789012:secret:TestEnv/db/password-AbCdEf",
				want:   policy.Allow,
			},
			{
				name:   "ProdEnv path",
				src:    docSMExamples,
				stated: "only names beginning with TestEnv/",
				action: "secretsmanager:GetSecretValue",
				res:    "arn:aws:secretsmanager:us-east-1:123456789012:secret:ProdEnv/db-AbCdEf",
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docResource: wildcards "within the individual segments of an ARN";
	// "You can use multiple * or ? characters in each segment."
	{
		"wildcard segments",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"dynamodb:*","Resource":"arn:aws:dynamodb:us-*-?:*:table/b*s_table"}}`,
		},
		[]cfCase{
			{
				name:   "segments with * and ?",
				src:    docResource,
				stated: "* any combination, ? any single character, per segment",
				action: "dynamodb:GetItem",
				res:    "arn:aws:dynamodb:us-east-2:111122223333:table/books_table",
				want:   policy.Allow,
			},
			{
				name:   "? needs one char",
				src:    docResource,
				stated: "? is any single character",
				action: "dynamodb:GetItem",
				res:    "arn:aws:dynamodb:us-east-12:111122223333:table/books_table",
				want:   policy.ImplicitDeny,
			},
			{
				name:   "table name mismatch",
				src:    docResource,
				stated: "table/b*s_table",
				action: "dynamodb:GetItem",
				res:    "arn:aws:dynamodb:us-east-2:111122223333:table/magazines_table",
				want:   policy.ImplicitDeny,
			},
		},
	},
}

func TestConformanceResources(t *testing.T) { cfRunGroups(t, cfResourceGroups) }

// ---------------------------------------------------------------------------
// Policy variables

var cfVariableGroups = []cfGroup{
	// Source: docS3Examples: "if Mary sends a request to put an object, the
	// operation is allowed only if Mary is uploading the object to the
	// amzn-s3-demo-bucket1/Mary folder."
	// Source: docVariables: a variable with no value in Resource "will not match
	// any resource".
	{
		"aws:username in Resource",
		[]string{"s3-username-folder.json"},
		[]cfCase{
			{
				name:   "own folder",
				src:    docS3Examples,
				stated: "allowed only if Mary uploads to the Mary folder",
				action: "s3:PutObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket1/Mary/notes.txt",
				ctx:    cfCtx{"aws:username": {"Mary"}},
				want:   policy.Allow,
			},
			{
				name:   "someone else's folder",
				src:    docS3Examples,
				stated: "allowed only if Mary uploads to the Mary folder",
				action: "s3:PutObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket1/Carlos/notes.txt",
				ctx:    cfCtx{"aws:username": {"Mary"}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "no username",
				src:    docVariables,
				stated: "a resource with a variable with no value will not match any resource",
				action: "s3:PutObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket1/Mary/notes.txt",
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docVersion / docVariables: without Version 2012-10-17 "variables
	// like ${aws:username} are treated as literal strings in the policy."
	{
		"no Version means literal",
		[]string{"s3-username-folder-noversion.json"},
		[]cfCase{
			{
				name:   "not substituted",
				src:    docVariables,
				stated: "treated as literal strings",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket1/Mary/notes.txt",
				ctx:    cfCtx{"aws:username": {"Mary"}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "literal text matches",
				src:    docVariables,
				stated: "treated as literal strings",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket1/${aws:username}/notes.txt",
				ctx:    cfCtx{"aws:username": {"Mary"}},
				want:   policy.Allow,
			},
		},
	},
	{
		"2008-10-17 means literal",
		[]string{
			`{"Version":"2008-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/${aws:username}/*"}}`,
		},
		[]cfCase{
			{
				name:   "not substituted",
				src:    docVersion,
				stated: "variables such as ${aws:username} aren't recognized as variables",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/Mary/x",
				ctx:    cfCtx{"aws:username": {"Mary"}},
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docS3Examples: folders based on IAM user IDs with ${aws:userid}.
	{
		"aws:userid",
		[]string{"s3-userid-folder.json"},
		[]cfCase{
			{
				name:   "own id folder",
				src:    docS3Examples,
				stated: "folders based on IAM user IDs",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket1/home/AIDAJQABLZS4A3QDU576Q/f",
				ctx:    cfCtx{"aws:userid": {"AIDAJQABLZS4A3QDU576Q"}},
				want:   policy.Allow,
			},
			{
				name:   "other id folder",
				src:    docS3Examples,
				stated: "folders based on IAM user IDs",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket1/home/AIDAOTHER/f",
				ctx:    cfCtx{"aws:userid": {"AIDAJQABLZS4A3QDU576Q"}},
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docOperators "Example using a policy variable with a string
	// condition operator": the table substitutes martha_rivera / nikki_wolf and
	// gives "No match" when aws:username is absent.
	{
		"aws:username in Condition and Resource",
		[]string{"s3-home-directory.json"},
		[]cfCase{
			{
				name:   "list own home",
				src:    docOperators,
				stated: `"home/martha_rivera/" after substitution`,
				action: "s3:ListBucket",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket",
				ctx: cfCtx{
					"aws:username": {"martha_rivera"},
					"s3:prefix":    {"home/martha_rivera/"},
				},
				want: policy.Allow,
			},
			{
				name:   "list other home",
				src:    docOperators,
				stated: "only home/${aws:username}/ is listed",
				action: "s3:ListBucket",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket",
				ctx: cfCtx{
					"aws:username": {"martha_rivera"},
					"s3:prefix":    {"home/nikki_wolf/"},
				},
				want: policy.ImplicitDeny,
			},
			{
				name:   "list home root",
				src:    docOperators,
				stated: `"home/" is an allowed prefix`,
				action: "s3:ListBucket",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket",
				ctx: cfCtx{
					"aws:username": {"martha_rivera"},
					"s3:prefix":    {"home/"},
				},
				want: policy.Allow,
			},
			{
				name:   "no username",
				src:    docOperators,
				stated: "No aws:username in the request context: No match",
				action: "s3:ListBucket",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket",
				ctx:    cfCtx{"s3:prefix": {"home/martha_rivera/"}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "own objects",
				src:    docOperators,
				stated: "s3:* on home/${aws:username}/*",
				action: "s3:PutObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket/home/martha_rivera/cv.pdf",
				ctx:    cfCtx{"aws:username": {"martha_rivera"}},
				want:   policy.Allow,
			},
			{
				name:   "other objects",
				src:    docOperators,
				stated: "s3:* only on own home",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket/home/nikki_wolf/cv.pdf",
				ctx:    cfCtx{"aws:username": {"martha_rivera"}},
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docS3Examples account boundary with aws:PrincipalAccount: "This
	// condition requires that the principal and the resource must be in the
	// same account."
	{
		"aws:PrincipalAccount",
		[]string{"s3-account-boundary.json", cfAllowAll},
		[]cfCase{
			{
				name:   "same account",
				src:    docS3Examples,
				stated: "principal and resource in the same account",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/k",
				ctx: cfCtx{
					"aws:PrincipalAccount": {"111122223333"},
					"aws:ResourceAccount":  {"111122223333"},
				},
				want: policy.Allow,
			},
			{
				name:   "other account",
				src:    docS3Examples,
				stated: "Deny effect blocks access ... unless the resource is in the account",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/k",
				ctx: cfCtx{
					"aws:PrincipalAccount": {"111122223333"},
					"aws:ResourceAccount":  {"999999999999"},
				},
				want: policy.ExplicitDeny,
				sid:  cfStr("DenyS3AccessOutsideMyBoundary"),
			},
		},
	},
	// Source: docVariables "Special characters": ${*}, ${?}, ${$} represent a
	// literal *, ? and $. docS3Examples: "to include the object key my$file in
	// a policy, specify it as my${$}file."
	{
		"escapes",
		[]string{
			`{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::b/my${$}file","arn:aws:s3:::b/star${*}","arn:aws:s3:::b/q${?}"]},
		{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b","Condition":{"StringLike":{"s3:prefix":"a${*}"}}}]}`,
		},
		[]cfCase{
			{
				name:   "dollar",
				src:    docS3Examples,
				stated: "my${$}file is the key my$file",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/my$file",
				want:   policy.Allow,
			},
			{
				name:   "literal star",
				src:    docVariables,
				stated: "${*} is a literal asterisk",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/star*",
				want:   policy.Allow,
			},
			{
				name:   "star not wildcard",
				src:    docVariables,
				stated: "instead of as a wildcard",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/starX",
				want:   policy.ImplicitDeny,
			},
			{
				name:   "literal question",
				src:    docVariables,
				stated: "${?} is a literal question mark",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/q?",
				want:   policy.Allow,
			},
			{
				name:   "question not wildcard",
				src:    docVariables,
				stated: "${?} is a literal question mark",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/qX",
				want:   policy.ImplicitDeny,
			},
			{
				name:   "escape in condition",
				src:    docVariables,
				stated: "usable in any string where variables are",
				action: "s3:ListBucket",
				res:    "arn:aws:s3:::b",
				ctx:    cfCtx{"s3:prefix": {"a*"}},
				want:   policy.Allow,
			},
			{
				name:   "escape in condition not wildcard",
				src:    docVariables,
				stated: "literal *",
				action: "s3:ListBucket",
				res:    "arn:aws:s3:::b",
				ctx:    cfCtx{"s3:prefix": {"abc"}},
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docVariables: "Key names are case-insensitive. For example,
	// aws:CurrentTime is equivalent to AWS:currenttime."
	{
		"variable name case",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/${AWS:UserName}/*"}}`,
		},
		[]cfCase{
			{
				name:   "mixed case variable",
				src:    docVariables,
				stated: "key names are case-insensitive",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::b/Mary/x",
				ctx:    cfCtx{"aws:username": {"Mary"}},
				want:   policy.Allow,
			},
		},
	},
	// The design lists ${aws:username}, ${aws:userid}, ${aws:PrincipalAccount};
	// AWS documents that any single-valued key can be a variable. The two
	// groups below use aws:PrincipalTag and the default-value syntax, which AWS
	// documents but the design does not list.
	//
	// Source: docVariables "Policy variables with no value": "Access is
	// explicitly denied when aws:principaltag/Team is not set."
	{
		"beyond design list: PrincipalTag",
		[]string{"variables-team-deny.json", cfAllowAll},
		[]cfCase{
			{
				name:   "team matches",
				src:    docVariables,
				stated: "PrincipalTag/Team must equal ExistingObjectTag/Team",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket/k",
				ctx: cfCtx{
					"s3:ExistingObjectTag/Team": {"red"},
					"aws:PrincipalTag/Team":     {"red"},
				},
				want: policy.Allow,
			},
			{
				name:   "team differs",
				src:    docVariables,
				stated: "must be equal to allow access",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket/k",
				ctx: cfCtx{
					"s3:ExistingObjectTag/Team": {"red"},
					"aws:PrincipalTag/Team":     {"blue"},
				},
				want: policy.ExplicitDeny,
			},
			{
				name:   "principal tag unset",
				src:    docVariables,
				stated: "explicitly denied when aws:principaltag/Team is not set",
				action: "s3:GetObject",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket/k",
				ctx:    cfCtx{"s3:ExistingObjectTag/Team": {"red"}},
				want:   policy.ExplicitDeny,
			},
		},
	},
	// Source: docVariables "Specifying default values": team=yellow reaches
	// amzn-s3-demo-bucket-yellow; "users without team tags ... can access
	// only the amzn-s3-demo-bucket-company-wide bucket"; not other teams'.
	{
		"beyond design list: default value",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::amzn-s3-demo-bucket-${aws:PrincipalTag/team, 'company-wide'}"}}`,
		},
		[]cfCase{
			{
				name:   "team bucket",
				src:    docVariables,
				stated: "team=yellow can access amzn-s3-demo-bucket-yellow",
				action: "s3:ListBucket",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket-yellow",
				ctx:    cfCtx{"aws:PrincipalTag/team": {"yellow"}},
				want:   policy.Allow,
			},
			{
				name:   "other team bucket",
				src:    docVariables,
				stated: "but not those of other teams",
				action: "s3:ListBucket",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket-blue",
				ctx:    cfCtx{"aws:PrincipalTag/team": {"yellow"}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "default",
				src:    docVariables,
				stated: "users without team tags access the company-wide bucket",
				action: "s3:ListBucket",
				res:    "arn:aws:s3:::amzn-s3-demo-bucket-company-wide",
				want:   policy.Allow,
			},
		},
	},
	// Source: docCondition: aws:MultiFactorAuthAge 2800 "is less than 3600, so
	// the policy allows this authorization request"; more than an hour returns
	// false; a missing key "won't match". (Adapted: the page's sample context is
	// an assumed role with a malformed resource; here an IAM user martha.)
	{
		"MFA age with username resource",
		[]string{"mfa-age.json"},
		[]cfCase{
			{
				name:   "recent MFA",
				src:    docCondition,
				stated: "2800 is less than 3600, so the policy allows",
				action: "iam:DeactivateMFADevice",
				res:    "arn:aws:iam::111122223333:user/martha",
				ctx:    cfCtx{"aws:username": {"martha"}, "aws:MultiFactorAuthAge": {"2800"}},
				want:   policy.Allow,
				sid:    cfStr("AllowRemoveMfaOnlyIfRecentMfa"),
			},
			{
				name:   "old MFA",
				src:    docCondition,
				stated: "more than one hour ago returns false",
				action: "iam:DeactivateMFADevice",
				res:    "arn:aws:iam::111122223333:user/martha",
				ctx:    cfCtx{"aws:username": {"martha"}, "aws:MultiFactorAuthAge": {"4000"}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "access keys",
				src:    docCondition,
				stated: "key not present, it won't match",
				action: "iam:DeactivateMFADevice",
				res:    "arn:aws:iam::111122223333:user/martha",
				ctx:    cfCtx{"aws:username": {"martha"}},
				want:   policy.ImplicitDeny,
			},
		},
	},
}

func TestConformanceVariables(t *testing.T) { cfRunGroups(t, cfVariableGroups) }

// ---------------------------------------------------------------------------
// Condition operators

// cfCond is one Condition element checked in an Allow statement on
// s3:ListBucket; match means Evaluate returns Allow.
//
//nolint:govet // fieldalignment: field order reads as the table rows do.
type cfCond struct {
	name   string
	src    string
	stated string
	cond   string // the Condition object
	ctx    cfCtx
	match  bool
}

func cfConds(t *testing.T, cases []cfCond) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*","Condition":` + c.cond + `}}`
			p := cfParse(t, doc)
			r := policy.Evaluate(
				policy.Request{
					Action:    "s3:ListBucket",
					Resource:  "arn:aws:s3:::b",
					Principal: cfUser,
					Context:   c.ctx,
				},
				p,
			)
			got := any(r.Decision) == policy.Allow
			if got != c.match {
				t.Errorf(
					"match = %v (Decision %v), want %v\n  condition: %s\n  ctx: %v\n  source: %s\n  AWS states: %s",
					got,
					r.Decision,
					c.match,
					c.cond,
					c.ctx,
					c.src,
					c.stated,
				)
			}
		})
	}
}

const cfJobCategory = `{"StringEquals":{"aws:PrincipalTag/job-category":"iamuser-admin"}}`

var cfStringConds = []cfCond{
	// Source: docOperators string example table.
	{
		"StringEquals match",
		docOperators,
		"Match",
		cfJobCategory,
		cfCtx{"aws:PrincipalTag/job-category": {"iamuser-admin"}},
		true,
	},
	{
		"StringEquals other value",
		docOperators,
		"No match",
		cfJobCategory,
		cfCtx{"aws:PrincipalTag/job-category": {"dev-ops"}},
		false,
	},
	{"StringEquals missing key", docOperators, "No match", cfJobCategory, nil, false},
	// Source: docCondition: StringEquals john: "Users named John are denied";
	// StringEqualsIgnoreCase "match users named john or John".
	{
		"StringEquals case sensitive",
		docCondition,
		"Users named John are denied",
		`{"StringEquals":{"aws:username":"john"}}`,
		cfCtx{"aws:username": {"John"}},
		false,
	},
	{
		"StringEqualsIgnoreCase",
		docCondition,
		"match users named john or John",
		`{"StringEqualsIgnoreCase":{"aws:username":"john"}}`,
		cfCtx{"aws:username": {"John"}},
		true,
	},
	// Source: docCondition: "Context key names are not case-sensitive ...
	// aws:SourceIP is equivalent to AWS:SourceIp."
	{
		"key name case insensitive",
		docCondition,
		"context key names are not case-sensitive",
		`{"StringEquals":{"AWS:UserName":"john"}}`,
		cfCtx{"aws:username": {"john"}},
		true,
	},
	// Source: docOperators "Important": negated operator with missing key is true.
	{
		"StringNotEquals missing key",
		docOperators,
		"requires the key is not matched and key not present: true",
		`{"StringNotEquals":{"aws:username":"john"}}`,
		nil,
		true,
	},
	{
		"StringNotLike missing key",
		docOperators,
		"StringNotLike with key not present: true",
		`{"StringNotLike":{"aws:username":"j*"}}`,
		nil,
		true,
	},
	// Source: docMultiKeys: negated operator values evaluate as NOR.
	{
		"StringNotEquals NOR hit",
		docMultiKeys,
		"NOR returns true only if all values evaluate to false",
		`{"StringNotEquals":{"aws:username":["ana","mary"]}}`,
		cfCtx{"aws:username": {"mary"}},
		false,
	},
	{
		"StringNotEquals NOR miss",
		docMultiKeys,
		"NOR returns true only if all values evaluate to false",
		`{"StringNotEquals":{"aws:username":["ana","mary"]}}`,
		cfCtx{"aws:username": {"nikki"}},
		true,
	},
	// Source: docOperators: StringNotEqualsIgnoreCase "Negated matching, ignoring case".
	{
		"StringNotEqualsIgnoreCase",
		docOperators,
		"negated matching, ignoring case",
		`{"StringNotEqualsIgnoreCase":{"aws:username":"john"}}`,
		cfCtx{"aws:username": {"JOHN"}},
		false,
	},
	// Source: docOperators StringLike: "Case-sensitive matching ... * and ?
	// anywhere in the string. You must specify wildcards to achieve partial
	// string matches." IfExists table: t1.micro matches t1.*, m2.micro does not.
	{
		"StringLike star",
		docOperators,
		"t1.micro matches t1.*",
		`{"StringLike":{"ec2:InstanceType":["t1.*","t2.*","m3.*"]}}`,
		cfCtx{"ec2:InstanceType": {"t1.micro"}},
		true,
	},
	{
		"StringLike star miss",
		docOperators,
		"m2.micro: No match",
		`{"StringLike":{"ec2:InstanceType":["t1.*","t2.*","m3.*"]}}`,
		cfCtx{"ec2:InstanceType": {"m2.micro"}},
		false,
	},
	{
		"StringLike needs wildcard",
		docOperators,
		"must specify wildcards for partial matches",
		`{"StringLike":{"ec2:InstanceType":"t1"}}`,
		cfCtx{"ec2:InstanceType": {"t1.micro"}},
		false,
	},
	{
		"StringLike case sensitive",
		docOperators,
		"Case-sensitive matching",
		`{"StringLike":{"ec2:InstanceType":"T1.*"}}`,
		cfCtx{"ec2:InstanceType": {"t1.micro"}},
		false,
	},
	{
		"StringLike question",
		docOperators,
		"? single-character wildcard",
		`{"StringLike":{"s3:prefix":"home?"}}`,
		cfCtx{"s3:prefix": {"home/"}},
		true,
	},
	{
		"StringLike question one char only",
		docOperators,
		"? single-character wildcard",
		`{"StringLike":{"s3:prefix":"home?"}}`,
		cfCtx{"s3:prefix": {"home//"}},
		false,
	},
	// Source: docS3Examples region example: StringNotLike sa-east-1.
	{
		"StringNotLike other",
		docS3Examples,
		"denied if the location constraint is not sa-east-1",
		`{"StringNotLike":{"s3:LocationConstraint":"sa-east-1"}}`,
		cfCtx{"s3:LocationConstraint": {"us-east-1"}},
		true,
	},
	{
		"StringNotLike same",
		docS3Examples,
		"only sa-east-1 is not denied",
		`{"StringNotLike":{"s3:LocationConstraint":"sa-east-1"}}`,
		cfCtx{"s3:LocationConstraint": {"sa-east-1"}},
		false,
	},
}

func TestConformanceConditionString(t *testing.T) { cfConds(t, cfStringConds) }

const cfMaxKeys = `{"NumericLessThanEquals":{"s3:max-keys":"10"}}`

var cfNumericConds = []cfCond{
	// Source: docOperators: "the requester can list up to 10 objects";
	// "only the operations that include the max-keys context key with a value
	// of less than or equal to 10 would be allowed"; missing key: no match.
	{
		"LessThanEquals equal",
		docOperators,
		"up to 10",
		cfMaxKeys,
		cfCtx{"s3:max-keys": {"10"}},
		true,
	},
	{
		"LessThanEquals below",
		docOperators,
		"up to 10",
		cfMaxKeys,
		cfCtx{"s3:max-keys": {"5"}},
		true,
	},
	{
		"LessThanEquals above",
		docOperators,
		"up to 10",
		cfMaxKeys,
		cfCtx{"s3:max-keys": {"11"}},
		false,
	},
	{"missing key", docOperators, "key not present: values do not match", cfMaxKeys, nil, false},
	// Source: docOperators numeric table ("Matching", "Less than", ...),
	// "comparing a key to an integer or decimal value".
	{
		"NumericEquals",
		docOperators,
		"Matching",
		`{"NumericEquals":{"s3:max-keys":"10"}}`,
		cfCtx{"s3:max-keys": {"10"}},
		true,
	},
	{
		"NumericEquals other",
		docOperators,
		"Matching",
		`{"NumericEquals":{"s3:max-keys":"10"}}`,
		cfCtx{"s3:max-keys": {"11"}},
		false,
	},
	{
		"NumericNotEquals",
		docOperators,
		"Negated matching",
		`{"NumericNotEquals":{"s3:max-keys":"10"}}`,
		cfCtx{"s3:max-keys": {"11"}},
		true,
	},
	{
		"NumericNotEquals missing",
		docOperators,
		"negated operator, key absent: true",
		`{"NumericNotEquals":{"s3:max-keys":"10"}}`,
		nil,
		true,
	},
	{
		"NumericLessThan equal",
		docOperators,
		`"Less than"`,
		`{"NumericLessThan":{"s3:max-keys":"10"}}`,
		cfCtx{"s3:max-keys": {"10"}},
		false,
	},
	{
		"NumericLessThan below",
		docOperators,
		`"Less than"`,
		`{"NumericLessThan":{"s3:max-keys":"10"}}`,
		cfCtx{"s3:max-keys": {"9"}},
		true,
	},
	{
		"NumericGreaterThan",
		docOperators,
		`"Greater than"`,
		`{"NumericGreaterThan":{"s3:max-keys":"10"}}`,
		cfCtx{"s3:max-keys": {"11"}},
		true,
	},
	{
		"NumericGreaterThan equal",
		docOperators,
		`"Greater than"`,
		`{"NumericGreaterThan":{"s3:max-keys":"10"}}`,
		cfCtx{"s3:max-keys": {"10"}},
		false,
	},
	{
		"NumericGreaterThanEquals",
		docOperators,
		`"Greater than or equals"`,
		`{"NumericGreaterThanEquals":{"s3:max-keys":"10"}}`,
		cfCtx{"s3:max-keys": {"10"}},
		true,
	},
	{
		"NumericGreaterThanEquals below",
		docOperators,
		`"Greater than or equals"`,
		`{"NumericGreaterThanEquals":{"s3:max-keys":"10"}}`,
		cfCtx{"s3:max-keys": {"9"}},
		false,
	},
	{
		"decimal",
		docOperators,
		"integer or decimal value",
		`{"NumericLessThan":{"x:ratio":"1.5"}}`,
		cfCtx{"x:ratio": {"1.25"}},
		true,
	},
	{
		"decimal above",
		docOperators,
		"integer or decimal value",
		`{"NumericLessThan":{"x:ratio":"1.5"}}`,
		cfCtx{"x:ratio": {"1.75"}},
		false,
	},
	// ASSUMPTION: numeric comparison is by value, so 10 equals 10.0 (AWS says
	// numeric operators compare integer or decimal values; no example).
	{
		"value not text",
		docOperators,
		"ASSUMPTION: compared as numbers",
		`{"NumericEquals":{"s3:max-keys":"10"}}`,
		cfCtx{"s3:max-keys": {"10.0"}},
		true,
	},
}

func TestConformanceConditionNumeric(t *testing.T) { cfConds(t, cfNumericConds) }

// Source: docExDates: "restricts access to actions that occur between April
// 1, 2020 and June 30, 2020 (UTC)".
var cfDateGroups = []cfGroup{
	{
		"dates example",
		[]string{"dates-range.json"},
		[]cfCase{
			{
				name:   "inside",
				src:    docExDates,
				stated: "access between April 1 and June 30, 2020",
				action: "service-prefix:action-name",
				res:    "*",
				ctx:    cfCtx{"aws:CurrentTime": {"2020-05-15T12:00:00Z"}},
				want:   policy.Allow,
			},
			{
				name:   "before",
				src:    docExDates,
				stated: "restricted to April 1 - June 30, 2020",
				action: "service-prefix:action-name",
				res:    "*",
				ctx:    cfCtx{"aws:CurrentTime": {"2020-03-31T23:00:00Z"}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "after",
				src:    docExDates,
				stated: "restricted to April 1 - June 30, 2020",
				action: "service-prefix:action-name",
				res:    "*",
				ctx:    cfCtx{"aws:CurrentTime": {"2020-07-01T00:00:00Z"}},
				want:   policy.ImplicitDeny,
			},
		},
	},
}

const (
	cfIssueTimeCond = `{"DateGreaterThan":{"aws:TokenIssueTime":"2020-01-01T00:00:01Z"}}`
	cfAt            = `"2020-04-01T00:00:00Z"`
)

var cfDateConds = []cfCond{
	// Source: docOperators date example: TokenIssueTime "issued in 2020";
	// key absent for access-key requests: "the request is denied".
	{
		"TokenIssueTime 2020",
		docOperators,
		"credentials issued in 2020",
		cfIssueTimeCond,
		cfCtx{"aws:TokenIssueTime": {"2020-06-01T00:00:00Z"}},
		true,
	},
	{
		"TokenIssueTime 2019",
		docOperators,
		"credentials issued in 2020",
		cfIssueTimeCond,
		cfCtx{"aws:TokenIssueTime": {"2019-12-31T00:00:00Z"}},
		false,
	},
	{
		"TokenIssueTime missing",
		docOperators,
		"IAM user with access keys: the request is denied",
		cfIssueTimeCond,
		nil,
		false,
	},
	// Source: docOperators date table descriptions.
	{
		"DateEquals",
		docOperators,
		"Matching a specific date",
		`{"DateEquals":{"aws:CurrentTime":` + cfAt + `}}`,
		cfCtx{"aws:CurrentTime": {"2020-04-01T00:00:00Z"}},
		true,
	},
	{
		"DateEquals other",
		docOperators,
		"Matching a specific date",
		`{"DateEquals":{"aws:CurrentTime":` + cfAt + `}}`,
		cfCtx{"aws:CurrentTime": {"2020-04-01T00:00:01Z"}},
		false,
	},
	{
		"DateNotEquals",
		docOperators,
		"Negated matching",
		`{"DateNotEquals":{"aws:CurrentTime":` + cfAt + `}}`,
		cfCtx{"aws:CurrentTime": {"2020-04-01T00:00:01Z"}},
		true,
	},
	{
		"DateLessThan",
		docOperators,
		"before a specific date and time",
		`{"DateLessThan":{"aws:CurrentTime":` + cfAt + `}}`,
		cfCtx{"aws:CurrentTime": {"2020-03-31T23:59:59Z"}},
		true,
	},
	{
		"DateLessThan equal",
		docOperators,
		"before a specific date and time",
		`{"DateLessThan":{"aws:CurrentTime":` + cfAt + `}}`,
		cfCtx{"aws:CurrentTime": {"2020-04-01T00:00:00Z"}},
		false,
	},
	{
		"DateLessThanEquals equal",
		docOperators,
		"at or before",
		`{"DateLessThanEquals":{"aws:CurrentTime":` + cfAt + `}}`,
		cfCtx{"aws:CurrentTime": {"2020-04-01T00:00:00Z"}},
		true,
	},
	{
		"DateGreaterThan equal",
		docOperators,
		"after a specific date and time",
		`{"DateGreaterThan":{"aws:CurrentTime":` + cfAt + `}}`,
		cfCtx{"aws:CurrentTime": {"2020-04-01T00:00:00Z"}},
		false,
	},
	{
		"DateGreaterThanEquals equal",
		docOperators,
		"at or after",
		`{"DateGreaterThanEquals":{"aws:CurrentTime":` + cfAt + `}}`,
		cfCtx{"aws:CurrentTime": {"2020-04-01T00:00:00Z"}},
		true,
	},
	// Source: docOperators: date values in ISO 8601 "or in epoch (UNIX) time";
	// docCondKeys aws:EpochTime: "accepts the number of seconds since January 1, 1970".
	// 1585699200 = 2020-04-01T00:00:00Z, 1589544000 = 2020-05-15T12:00:00Z.
	{
		"epoch policy and request",
		docCondKeys,
		"epoch (UNIX) time",
		`{"DateGreaterThan":{"aws:EpochTime":"1585699200"}}`,
		cfCtx{"aws:EpochTime": {"1589544000"}},
		true,
	},
	{
		"epoch earlier",
		docCondKeys,
		"epoch (UNIX) time",
		`{"DateGreaterThan":{"aws:EpochTime":"1585699200"}}`,
		cfCtx{"aws:EpochTime": {"1585000000"}},
		false,
	},
	// ASSUMPTION: a policy value in one accepted form compares with a request
	// value in the other (both denote instants; no AWS example mixes them).
	{
		"ISO policy vs epoch request",
		docOperators,
		"ASSUMPTION: forms interchangeable",
		`{"DateGreaterThan":{"aws:EpochTime":` + cfAt + `}}`,
		cfCtx{"aws:EpochTime": {"1589544000"}},
		true,
	},
	{
		"epoch policy vs ISO request",
		docOperators,
		"ASSUMPTION: forms interchangeable",
		`{"DateLessThan":{"aws:CurrentTime":"1585699200"}}`,
		cfCtx{"aws:CurrentTime": {"2020-03-01T00:00:00Z"}},
		true,
	},
	// Source: docOperators requires "one of the W3C implementations of the ISO
	// 8601 date formats" (docW3CDatetime lists YYYY-MM-DD, offsets as +hh:mm,
	// and fractional seconds). Outcomes follow from the format's meaning.
	{
		"W3C date only",
		docW3CDatetime,
		"YYYY-MM-DD is a valid W3C form",
		`{"DateGreaterThan":{"aws:CurrentTime":"2020-04-01"}}`,
		cfCtx{"aws:CurrentTime": {"2020-04-02T00:00:00Z"}},
		true,
	},
	{
		"W3C date only before",
		docW3CDatetime,
		"YYYY-MM-DD is a valid W3C form",
		`{"DateGreaterThan":{"aws:CurrentTime":"2020-04-01"}}`,
		cfCtx{"aws:CurrentTime": {"2020-03-31T00:00:00Z"}},
		false,
	},
	{
		"W3C offset",
		docW3CDatetime,
		"+02:00 offset denotes the same instant",
		`{"DateEquals":{"aws:CurrentTime":"2020-04-01T02:00:00+02:00"}}`,
		cfCtx{"aws:CurrentTime": {"2020-04-01T00:00:00Z"}},
		true,
	},
	{
		"W3C fraction",
		docW3CDatetime,
		"fractional seconds",
		`{"DateGreaterThan":{"aws:CurrentTime":"2020-04-01T00:00:00.500Z"}}`,
		cfCtx{"aws:CurrentTime": {"2020-04-01T00:00:01Z"}},
		true,
	},
}

func TestConformanceConditionDate(t *testing.T) {
	cfRunGroups(t, cfDateGroups)
	cfConds(t, cfDateConds)
}

const (
	cfSecureTransport = `{"Bool":{"aws:SecureTransport":"false"}}`
	cfBinary          = `{"BinaryEquals":{"svc:key":"QmluYXJ5VmFsdWVJbkJhc2U2NA=="}}`
)

var cfBoolBinaryConds = []cfCond{
	// Source: docOperators boolean example table.
	{
		"Bool false/false",
		docOperators,
		"Match",
		cfSecureTransport,
		cfCtx{"aws:SecureTransport": {"false"}},
		true,
	},
	{
		"Bool false/true",
		docOperators,
		"No match",
		cfSecureTransport,
		cfCtx{"aws:SecureTransport": {"true"}},
		false,
	},
	{"Bool missing", docOperators, "No match", cfSecureTransport, nil, false},
	// Source: docCondKeys aws:MultiFactorAuthPresent: Allow with BoolIfExists
	// true "allows MFA-authenticated requests and long-term credential
	// requests. It does not allow temporary credentials without MFA."
	{
		"BoolIfExists true/true",
		docCondKeys,
		"allows MFA-authenticated requests",
		`{"BoolIfExists":{"aws:MultiFactorAuthPresent":"true"}}`,
		cfCtx{"aws:MultiFactorAuthPresent": {"true"}},
		true,
	},
	{
		"BoolIfExists true/absent",
		docCondKeys,
		"allows long-term credential requests",
		`{"BoolIfExists":{"aws:MultiFactorAuthPresent":"true"}}`,
		nil,
		true,
	},
	{
		"BoolIfExists true/false",
		docCondKeys,
		"does not allow temporary credentials without MFA",
		`{"BoolIfExists":{"aws:MultiFactorAuthPresent":"true"}}`,
		cfCtx{"aws:MultiFactorAuthPresent": {"false"}},
		false,
	},
	// Source: docCondKeys: Bool true with Allow "excludes long-term credential requests".
	{
		"Bool true/absent",
		docCondKeys,
		"excludes long-term credential requests",
		`{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`,
		nil,
		false,
	},
	// Source: docOperators binary table ({{key}} placeholder written as svc:key).
	{
		"BinaryEquals match",
		docOperators,
		"Match",
		cfBinary,
		cfCtx{"svc:key": {"QmluYXJ5VmFsdWVJbkJhc2U2NA=="}},
		true,
	},
	{
		"BinaryEquals other",
		docOperators,
		"No match",
		cfBinary,
		cfCtx{"svc:key": {"ASIAIOSFODNN7EXAMPLE"}},
		false,
	},
	{"BinaryEquals missing", docOperators, "No match", cfBinary, nil, false},
}

func TestConformanceConditionBoolBinary(t *testing.T) { cfConds(t, cfBoolBinaryConds) }

const cfRange24 = `{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`

var cfIPConds = []cfCond{
	// Source: docOperators IP example: "the request must come from the IP
	// range 203.0.113.0 to 203.0.113.255"; table 203.0.113.1 Match,
	// 198.51.100.1 No match.
	{"in range", docOperators, "Match", cfRange24, cfCtx{"aws:SourceIp": {"203.0.113.1"}}, true},
	{
		"out of range",
		docOperators,
		"No match",
		cfRange24,
		cfCtx{"aws:SourceIp": {"198.51.100.1"}},
		false,
	},
	{
		"range top",
		docOperators,
		"range 203.0.113.0 to 203.0.113.255",
		cfRange24,
		cfCtx{"aws:SourceIp": {"203.0.113.255"}},
		true,
	},
	{
		"just above range",
		docOperators,
		"range 203.0.113.0 to 203.0.113.255",
		cfRange24,
		cfCtx{"aws:SourceIp": {"203.0.114.0"}},
		false,
	},
	{
		"missing key",
		docOperators,
		"key not present (VPC endpoint): condition returns false",
		cfRange24,
		nil,
		false,
	},
	// Source: docOperators: "If you specify an IP address without the
	// associated routing prefix, IAM uses the default prefix value of /32."
	{
		"no prefix is /32",
		docOperators,
		"default prefix /32",
		`{"IpAddress":{"aws:SourceIp":"203.0.113.7"}}`,
		cfCtx{"aws:SourceIp": {"203.0.113.7"}},
		true,
	},
	{
		"no prefix is /32 miss",
		docOperators,
		"default prefix /32",
		`{"IpAddress":{"aws:SourceIp":"203.0.113.7"}}`,
		cfCtx{"aws:SourceIp": {"203.0.113.8"}},
		false,
	},
	// Source: docOperators "Important": negated operator, key absent: true.
	{
		"NotIpAddress missing",
		docOperators,
		"negated operator with key not present: true",
		`{"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`,
		nil,
		true,
	},
	{
		"NotIpAddress outside",
		docOperators,
		"All IP addresses except the specified range",
		`{"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`,
		cfCtx{"aws:SourceIp": {"198.51.100.1"}},
		true,
	},
	{
		"NotIpAddress inside",
		docOperators,
		"All IP addresses except the specified range",
		`{"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`,
		cfCtx{"aws:SourceIp": {"203.0.113.9"}},
		false,
	},
}

// Source: docOperators: mixing IPv4 and IPv6 "to cover all of your
// organization's valid IP addresses"; IPv6 CIDR 2001:DB8:1234:5678::/64.
var cfIPGroups = []cfGroup{
	{
		"IPv4 and IPv6",
		[]string{"ip-v4-v6.json"},
		[]cfCase{
			{
				name:   "ipv6 in /64 lowercase",
				src:    docOperators,
				stated: "2001:DB8:1234:5678::/64 covers the organization",
				action: "someservice:Do",
				res:    "*",
				ctx:    cfCtx{"aws:SourceIp": {"2001:db8:1234:5678::1"}},
				want:   policy.Allow,
			},
			{
				name:   "ipv6 top of /64",
				src:    docOperators,
				stated: "2001:DB8:1234:5678::/64",
				action: "someservice:Do",
				res:    "*",
				ctx:    cfCtx{"aws:SourceIp": {"2001:db8:1234:5678:ffff:ffff:ffff:ffff"}},
				want:   policy.Allow,
			},
			{
				name:   "ipv6 outside /64",
				src:    docOperators,
				stated: "2001:DB8:1234:5678::/64",
				action: "someservice:Do",
				res:    "*",
				ctx:    cfCtx{"aws:SourceIp": {"2001:db8:1234:5679::1"}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "ipv4 still covered",
				src:    docOperators,
				stated: "203.0.113.0/24",
				action: "someservice:Do",
				res:    "*",
				ctx:    cfCtx{"aws:SourceIp": {"203.0.113.9"}},
				want:   policy.Allow,
			},
		},
	},
}

func TestConformanceConditionIP(t *testing.T) {
	cfConds(t, cfIPConds)
	cfRunGroups(t, cfIPGroups)
}

const cfSourceArn = `{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:us-west-2:123456789012:TOPIC-ID"}}`

var cfARNConds = []cfCond{
	// Source: docOperators ARN example table.
	{
		"ArnEquals match",
		docOperators,
		"Match",
		cfSourceArn,
		cfCtx{"aws:SourceArn": {"arn:aws:sns:us-west-2:123456789012:TOPIC-ID"}},
		true,
	},
	{
		"ArnEquals other account",
		docOperators,
		"No match",
		cfSourceArn,
		cfCtx{"aws:SourceArn": {"arn:aws:sns:us-west-2:777788889999:TOPIC-ID"}},
		false,
	},
	{"ArnEquals missing", docOperators, "No match", cfSourceArn, nil, false},
	// Source: docOperators: "Case-sensitive matching of the ARN. Each of the
	// six colon-delimited components ... can include * or ?. The ArnEquals
	// and ArnLike condition operators behave identically."
	{
		"ArnLike wildcards",
		docOperators,
		"each component can include * or ?",
		`{"ArnLike":{"aws:SourceArn":"arn:aws:sns:*:123456789012:TOPIC-??"}}`,
		cfCtx{"aws:SourceArn": {"arn:aws:sns:us-west-2:123456789012:TOPIC-ID"}},
		true,
	},
	{
		"ArnEquals wildcards identical",
		docOperators,
		"ArnEquals and ArnLike behave identically",
		`{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:*:123456789012:*"}}`,
		cfCtx{"aws:SourceArn": {"arn:aws:sns:us-west-2:123456789012:TOPIC-ID"}},
		true,
	},
	{
		"ArnLike case sensitive",
		docOperators,
		"Case-sensitive matching",
		`{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::222222222222:user/Ana"}}`,
		cfCtx{"aws:PrincipalArn": {"arn:aws:iam::222222222222:user/ana"}},
		false,
	},
	{
		"ArnNotEquals missing",
		docOperators,
		"ArnNotLike with key not present: true",
		`{"ArnNotEquals":{"aws:SourceArn":"arn:aws:sns:us-west-2:123456789012:TOPIC-ID"}}`,
		nil,
		true,
	},
	{
		"ArnNotLike match",
		docOperators,
		"Negated matching for ARN",
		`{"ArnNotLike":{"aws:SourceArn":"arn:aws:sns:*:123456789012:*"}}`,
		cfCtx{"aws:SourceArn": {"arn:aws:sns:us-west-2:123456789012:TOPIC-ID"}},
		false,
	},
}

func TestConformanceConditionARN(t *testing.T) { cfConds(t, cfARNConds) }

var cfNullConds = []cfCond{
	// Source: docOperators Null: "true (the key doesn't exist - it is null)
	// or false (the key exists and its value is not null)"; example requires
	// temporary credentials (aws:TokenIssueTime present).
	{
		"Null false present",
		docOperators,
		"key exists: false matches",
		`{"Null":{"aws:TokenIssueTime":"false"}}`,
		cfCtx{"aws:TokenIssueTime": {"2020-06-01T00:00:00Z"}},
		true,
	},
	{
		"Null false absent",
		docOperators,
		"user must be using temporary credentials",
		`{"Null":{"aws:TokenIssueTime":"false"}}`,
		nil,
		false,
	},
	{
		"Null true absent",
		docOperators,
		"true: the key doesn't exist",
		`{"Null":{"aws:TokenIssueTime":"true"}}`,
		nil,
		true,
	},
	{
		"Null true present",
		docOperators,
		"true: the key doesn't exist",
		`{"Null":{"aws:TokenIssueTime":"true"}}`,
		cfCtx{"aws:TokenIssueTime": {"2020-06-01T00:00:00Z"}},
		false,
	},
}

const cfAWSManagedKey = "arn:aws:kms:us-east-1:123456789012:key/aws-managed"

var cfIfExistsGroups = []cfGroup{
	// Source: docOperators IfExists table: t1.micro Match, m2.micro No match,
	// no ec2:InstanceType Match.
	{
		"StringLikeIfExists example",
		[]string{"ifexists-instancetype.json"},
		[]cfCase{
			{
				name:   "t1.micro",
				src:    docOperators,
				stated: "Match",
				action: "ec2:RunInstances",
				res:    "*",
				ctx:    cfCtx{"ec2:InstanceType": {"t1.micro"}},
				want:   policy.Allow,
				sid:    cfStr("RunInstance"),
			},
			{
				name:   "m2.micro",
				src:    docOperators,
				stated: "No match",
				action: "ec2:RunInstances",
				res:    "*",
				ctx:    cfCtx{"ec2:InstanceType": {"m2.micro"}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "no instance type",
				src:    docOperators,
				stated: "Match",
				action: "ec2:RunInstances",
				res:    "arn:aws:ec2:us-east-1::image/ami-1",
				want:   policy.Allow,
			},
		},
	},
	// Source: docOperators IfExists: "If you are using an Effect: Deny element
	// with a negated condition operator like StringNotEqualsIfExists, the
	// request is still denied even if the condition key is not present."
	{
		"deny negated IfExists missing key",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringNotEqualsIfExists":{"aws:RequestedRegion":"eu-west-1"}}}}`,
			cfAllowAll,
		},
		[]cfCase{
			{
				name:   "key absent denied",
				src:    docOperators,
				stated: "still denied even if the condition key is not present",
				action: "s3:GetObject",
				res:    "*",
				want:   policy.ExplicitDeny,
				pol:    cfInt(0),
			},
			{
				name:   "key equal not denied",
				src:    docOperators,
				stated: "negated operator does not match the listed value",
				action: "s3:GetObject",
				res:    "*",
				ctx:    cfCtx{"aws:RequestedRegion": {"eu-west-1"}},
				want:   policy.Allow,
			},
		},
	},
	// Source: docSMExamples "Deny the AWS managed key aws/secretsmanager":
	// first statement denies creating or updating with the managed key; the
	// second "denies requests for creating secrets that don't include a KMS key".
	{
		"secrets manager key guard",
		[]string{"secrets-deny-managed-key.json", cfAllowAll},
		[]cfCase{
			{
				name:   "update with managed key",
				src:    docSMExamples,
				stated: "denies updating secrets using the AWS managed key",
				action: "secretsmanager:UpdateSecret",
				res:    "*",
				ctx:    cfCtx{"secretsmanager:KmsKeyArn": {cfAWSManagedKey}},
				want:   policy.ExplicitDeny,
				sid:    cfStr("RequireCustomerManagedKeysOnSecrets"),
			},
			{
				name:   "create without key",
				src:    docSMExamples,
				stated: "denies creating secrets that don't include a KMS key",
				action: "secretsmanager:CreateSecret",
				res:    "*",
				want:   policy.ExplicitDeny,
				pol:    cfInt(0),
			},
			{
				name:   "create with customer key",
				src:    docSMExamples,
				stated: "requires a customer managed key",
				action: "secretsmanager:CreateSecret",
				res:    "*",
				ctx: cfCtx{
					"secretsmanager:KmsKeyArn": {"arn:aws:kms:us-east-1:123456789012:key/customer"},
				},
				want: policy.Allow,
				pol:  cfInt(1),
			},
		},
	},
}

func TestConformanceConditionNullIfExists(t *testing.T) {
	cfConds(t, cfNullConds)
	cfRunGroups(t, cfIfExistsGroups)
}

const (
	cfInstance      = "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc"
	cfDistribution  = "arn:aws:cloudfront::123456789012:distribution/"
	cfDeliverySrc   = "arn:aws:logs:us-east-1:123456789012:delivery-source:src1"
	cfLogGenerating = "logs:LogGeneratingResourceArns"
)

var cfSetGroups = []cfGroup{
	// Source: docSetOps ForAllValues example table (with Null false).
	{
		"ForAllValues with Null",
		[]string{"forallvalues-tagkeys.json"},
		[]cfCase{
			{
				name:   "environment",
				src:    docSetOps,
				stated: "Match",
				action: "ec2:DeleteTags",
				res:    cfInstance,
				ctx:    cfCtx{"aws:TagKeys": {"environment"}},
				want:   policy.Allow,
			},
			{
				name:   "cost-center",
				src:    docSetOps,
				stated: "Match",
				action: "ec2:DeleteTags",
				res:    cfInstance,
				ctx:    cfCtx{"aws:TagKeys": {"cost-center"}},
				want:   policy.Allow,
			},
			{
				name:   "both",
				src:    docSetOps,
				stated: "Match",
				action: "ec2:DeleteTags",
				res:    cfInstance,
				ctx:    cfCtx{"aws:TagKeys": {"environment", "cost-center"}},
				want:   policy.Allow,
			},
			{
				name:   "environment and dept",
				src:    docSetOps,
				stated: "No match",
				action: "ec2:DeleteTags",
				res:    cfInstance,
				ctx:    cfCtx{"aws:TagKeys": {"environment", "dept"}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "missing",
				src:    docSetOps,
				stated: "No match (Null check prevents matching)",
				action: "ec2:DeleteTags",
				res:    cfInstance,
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docSetOps ForAnyValue example table.
	{
		"ForAnyValue",
		[]string{"foranyvalue-tagkeys.json"},
		[]cfCase{
			{
				name:   "environment",
				src:    docSetOps,
				stated: "Match",
				action: "ec2:DeleteTags",
				res:    cfInstance,
				ctx:    cfCtx{"aws:TagKeys": {"environment"}},
				want:   policy.Allow,
			},
			{
				name:   "cost-center",
				src:    docSetOps,
				stated: "Match",
				action: "ec2:DeleteTags",
				res:    cfInstance,
				ctx:    cfCtx{"aws:TagKeys": {"cost-center"}},
				want:   policy.Allow,
			},
			{
				name:   "both",
				src:    docSetOps,
				stated: "Match",
				action: "ec2:DeleteTags",
				res:    cfInstance,
				ctx:    cfCtx{"aws:TagKeys": {"environment", "cost-center"}},
				want:   policy.Allow,
			},
			{
				name:   "environment and dept",
				src:    docSetOps,
				stated: "Match",
				action: "ec2:DeleteTags",
				res:    cfInstance,
				ctx:    cfCtx{"aws:TagKeys": {"environment", "dept"}},
				want:   policy.Allow,
			},
			{
				name:   "dept",
				src:    docSetOps,
				stated: "No match",
				action: "ec2:DeleteTags",
				res:    cfInstance,
				ctx:    cfCtx{"aws:TagKeys": {"dept"}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "missing",
				src:    docSetOps,
				stated: "No match",
				action: "ec2:DeleteTags",
				res:    cfInstance,
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docOperators "Example using ForAnyValue with a string condition
	// operator" table (StringEqualsIgnoreCase + ForAnyValue:StringEquals).
	{
		"CreateTags IgnoreCase and ForAnyValue",
		[]string{"createtags-ignorecase.json"},
		[]cfCase{
			{
				name:   "row1",
				src:    docOperators,
				stated: "Match",
				action: "ec2:CreateTags",
				res:    cfInstance,
				ctx: cfCtx{
					"aws:TagKeys":                {"environment"},
					"aws:RequestTag/environment": {"preprod"},
				},
				want: policy.Allow,
			},
			{
				name:   "row2 PreProd",
				src:    docOperators,
				stated: "Match",
				action: "ec2:CreateTags",
				res:    cfInstance,
				ctx: cfCtx{
					"aws:TagKeys":                {"environment", "costcenter"},
					"aws:RequestTag/environment": {"PreProd"},
				},
				want: policy.Allow,
			},
			{
				name:   "row3 Environment key",
				src:    docOperators,
				stated: "No match (ForAnyValue comparison is case sensitive)",
				action: "ec2:CreateTags",
				res:    cfInstance,
				ctx: cfCtx{
					"aws:TagKeys":                {"Environment"},
					"aws:RequestTag/Environment": {"preprod"},
				},
				want: policy.ImplicitDeny,
			},
			{
				name:   "row4 costcenter",
				src:    docOperators,
				stated: "No match",
				action: "ec2:CreateTags",
				res:    cfInstance,
				ctx: cfCtx{
					"aws:TagKeys":                {"costcenter"},
					"aws:RequestTag/environment": {"preprod"},
				},
				want: policy.ImplicitDeny,
			},
			{
				name:   "row5 no TagKeys",
				src:    docOperators,
				stated: "No match",
				action: "ec2:CreateTags",
				res:    cfInstance,
				ctx:    cfCtx{"aws:RequestTag/environment": {"storage"}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "row6 no RequestTag",
				src:    docOperators,
				stated: "No match",
				action: "ec2:CreateTags",
				res:    cfInstance,
				ctx:    cfCtx{"aws:TagKeys": {"environment"}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "row7 neither",
				src:    docOperators,
				stated: "No match",
				action: "ec2:CreateTags",
				res:    cfInstance,
				want:   policy.ImplicitDeny,
			},
		},
	},
	// Source: docOperators "Example using ForAllValues with an ARN condition
	// operator" table; the last row: key absent is "Match", and "The
	// ForAllValues qualifier returns true if there are no context keys".
	// (The page's table writes ARNs as arn:aws::cloudfront:...; the policy JSON
	// writes arn:aws:cloudfront::...; the JSON form is used here.)
	{
		"ForAllValues ArnLike",
		[]string{"forallvalues-arnlike.json"},
		[]cfCase{
			{
				name:   "one",
				src:    docOperators,
				stated: "Match",
				action: "logs:PutDeliverySource",
				res:    cfDeliverySrc,
				ctx:    cfCtx{cfLogGenerating: {cfDistribution + "costcenter"}},
				want:   policy.Allow,
			},
			{
				name:   "two",
				src:    docOperators,
				stated: "Match",
				action: "logs:PutDeliverySource",
				res:    cfDeliverySrc,
				ctx: cfCtx{
					cfLogGenerating: {
						cfDistribution + "costcenter",
						cfDistribution + "support2025",
					},
				},
				want: policy.Allow,
			},
			{
				name:   "two admin",
				src:    docOperators,
				stated: "Match",
				action: "logs:PutDeliverySource",
				res:    cfDeliverySrc,
				ctx: cfCtx{
					cfLogGenerating: {cfDistribution + "costcenter", cfDistribution + "admin"},
				},
				want: policy.Allow,
			},
			{
				name:   "other account",
				src:    docOperators,
				stated: "No match",
				action: "logs:PutDeliverySource",
				res:    cfDeliverySrc,
				ctx: cfCtx{
					cfLogGenerating: {"arn:aws:cloudfront::777788889999:distribution/costcenter"},
				},
				want: policy.ImplicitDeny,
			},
			{
				name:   "missing",
				src:    docOperators,
				stated: "Match",
				action: "logs:PutDeliverySource",
				res:    cfDeliverySrc,
				want:   policy.Allow,
			},
		},
	},
	// Source: docSetOps ForAnyValue: "When using ForAnyValue with a Deny effect,
	// if the context key is not present in the request, the policy evaluates as
	// No match."
	{
		"ForAnyValue Deny missing key",
		[]string{
			`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"ForAnyValue:StringEquals":{"aws:TagKeys":["secret"]}}}}`,
			cfAllowAll,
		},
		[]cfCase{
			{
				name:   "missing key not denied",
				src:    docSetOps,
				stated: "evaluates as No match",
				action: "ec2:CreateTags",
				res:    "*",
				want:   policy.Allow,
			},
			{
				name:   "key present denied",
				src:    docSetOps,
				stated: "Match",
				action: "ec2:CreateTags",
				res:    "*",
				ctx:    cfCtx{"aws:TagKeys": {"a", "secret"}},
				want:   policy.ExplicitDeny,
			},
		},
	},
}

var cfSetConds = []cfCond{
	// Source: docSetOps ForAllValues: "It also returns true if there are no
	// context keys in the request."
	{
		"ForAllValues missing key",
		docSetOps,
		"returns true if there are no context keys",
		`{"ForAllValues:StringEquals":{"aws:TagKeys":["environment"]}}`,
		nil,
		true,
	},
	// ASSUMPTION: a key present with an empty slice is the "null dataset"
	// docOperators mentions ("returns true if ... the context key value
	// resolves to a null dataset, such as an empty string").
	{
		"ForAllValues empty set",
		docOperators,
		"ASSUMPTION: empty slice is a null dataset: true",
		`{"ForAllValues:StringEquals":{"aws:TagKeys":["environment"]}}`,
		cfCtx{"aws:TagKeys": {}},
		true,
	},
	// ASSUMPTION: same representation; docSetOps: ForAnyValue "For no
	// matching context key or if the key does not exist, returns false".
	{
		"ForAnyValue empty set",
		docSetOps,
		"ASSUMPTION: empty slice has no matching value: false",
		`{"ForAnyValue:StringEquals":{"aws:TagKeys":["environment"]}}`,
		cfCtx{"aws:TagKeys": {}},
		false,
	},
	// Source: docOperators multivalued string table: ForAllValues:StringNotEquals
	// "None of the values ... can match"; ForAnyValue:StringNotEquals "At
	// least one ... must NOT match".
	{
		"ForAllValues:StringNotEquals none match",
		docOperators,
		"None of the values can match",
		`{"ForAllValues:StringNotEquals":{"aws:TagKeys":["secret"]}}`,
		cfCtx{"aws:TagKeys": {"a", "b"}},
		true,
	},
	{
		"ForAllValues:StringNotEquals one matches",
		docOperators,
		"None of the values can match",
		`{"ForAllValues:StringNotEquals":{"aws:TagKeys":["secret"]}}`,
		cfCtx{"aws:TagKeys": {"a", "secret"}},
		false,
	},
	{
		"ForAnyValue:StringNotEquals one differs",
		docOperators,
		"At least one must NOT match",
		`{"ForAnyValue:StringNotEquals":{"aws:TagKeys":["secret"]}}`,
		cfCtx{"aws:TagKeys": {"a", "secret"}},
		true,
	},
	{
		"ForAnyValue:StringNotEquals all equal",
		docOperators,
		"At least one must NOT match",
		`{"ForAnyValue:StringNotEquals":{"aws:TagKeys":["secret"]}}`,
		cfCtx{"aws:TagKeys": {"secret"}},
		false,
	},
	{
		"ForAllValues:StringLike",
		docOperators,
		"All values must match at least one",
		`{"ForAllValues:StringLike":{"aws:TagKeys":["env*","cost*"]}}`,
		cfCtx{"aws:TagKeys": {"environment", "cost-center"}},
		true,
	},
	{
		"ForAnyValue:StringLike",
		docOperators,
		"At least one value must match",
		`{"ForAnyValue:StringLike":{"aws:TagKeys":["env*"]}}`,
		cfCtx{"aws:TagKeys": {"dept", "environment"}},
		true,
	},
}

func TestConformanceConditionSets(t *testing.T) {
	cfRunGroups(t, cfSetGroups)
	cfConds(t, cfSetConds)
}

// Source: docMultiKeys: operators AND, keys within an operator AND, values
// within a key OR, negated values NOR. Both tables, with the bucket policy's
// Principal removed so the Condition block runs as an identity policy.
const (
	cfMary  = "arn:aws:iam::222222222222:user/Mary"
	cfNikki = "arn:aws:iam::222222222222:user/Nikki"
	cfDept  = "aws:PrincipalTag/department"
	cfRole  = "aws:PrincipalTag/role"
	cfPArn  = "aws:PrincipalArn"
	cfDemoB = "arn:aws:s3:::amzn-s3-demo-bucket"
)

var cfAndOrGroups = []cfGroup{
	{
		"StringEquals and ArnLike",
		[]string{"multi-keys-and-or.json"},
		[]cfCase{
			{
				name:   "legal audit Mary",
				src:    docMultiKeys,
				stated: "Match",
				action: "s3:ListBucket",
				res:    cfDemoB,
				ctx:    cfCtx{cfDept: {"legal"}, cfRole: {"audit"}, cfPArn: {cfMary}},
				want:   policy.Allow,
			},
			{
				name:   "hr audit Nikki",
				src:    docMultiKeys,
				stated: "No match",
				action: "s3:ListBucket",
				res:    cfDemoB,
				ctx: cfCtx{
					cfDept: {"hr"},
					cfRole: {"audit"},
					cfPArn: {cfNikki},
				},
				want: policy.ImplicitDeny,
			},
			{
				name:   "hr payroll Mary",
				src:    docMultiKeys,
				stated: "No match",
				action: "s3:ListBucket",
				res:    cfDemoB,
				ctx: cfCtx{
					cfDept: {"hr"},
					cfRole: {"payroll"},
					cfPArn: {cfMary},
				},
				want: policy.ImplicitDeny,
			},
			{
				name:   "no role tag",
				src:    docMultiKeys,
				stated: "No match",
				action: "s3:ListBucket",
				res:    cfDemoB,
				ctx:    cfCtx{cfDept: {"hr"}, cfPArn: {cfMary}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "no tags",
				src:    docMultiKeys,
				stated: "No match",
				action: "s3:ListBucket",
				res:    cfDemoB,
				ctx:    cfCtx{cfPArn: {cfMary}},
				want:   policy.ImplicitDeny,
			},
		},
	},
	{
		"StringEquals and ArnNotLike",
		[]string{"multi-keys-nor.json"},
		[]cfCase{
			{
				name:   "legal audit Nikki",
				src:    docMultiKeys,
				stated: "Match",
				action: "s3:ListBucket",
				res:    cfDemoB,
				ctx:    cfCtx{cfDept: {"legal"}, cfRole: {"audit"}, cfPArn: {cfNikki}},
				want:   policy.Allow,
			},
			{
				name:   "hr audit Mary",
				src:    docMultiKeys,
				stated: "No match",
				action: "s3:ListBucket",
				res:    cfDemoB,
				ctx: cfCtx{
					cfDept: {"hr"},
					cfRole: {"audit"},
					cfPArn: {cfMary},
				},
				want: policy.ImplicitDeny,
			},
			{
				name:   "hr payroll Nikki",
				src:    docMultiKeys,
				stated: "No match",
				action: "s3:ListBucket",
				res:    cfDemoB,
				ctx: cfCtx{
					cfDept: {"hr"},
					cfRole: {"payroll"},
					cfPArn: {cfNikki},
				},
				want: policy.ImplicitDeny,
			},
			{
				name:   "no role tag",
				src:    docMultiKeys,
				stated: "No match",
				action: "s3:ListBucket",
				res:    cfDemoB,
				ctx:    cfCtx{cfDept: {"hr"}, cfPArn: {cfNikki}},
				want:   policy.ImplicitDeny,
			},
			{
				name:   "no tags",
				src:    docMultiKeys,
				stated: "No match",
				action: "s3:ListBucket",
				res:    cfDemoB,
				ctx:    cfCtx{cfPArn: {cfNikki}},
				want:   policy.ImplicitDeny,
			},
		},
	},
}

func TestConformanceConditionAndOr(t *testing.T) { cfRunGroups(t, cfAndOrGroups) }

// Not from AWS: the design says "Unknown operators fail closed (the statement
// does not apply for Allow; documented)". Parse may refuse the document
// instead; either way the request must not be allowed.
func TestConformanceUnknownOperatorFailsClosed(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringSoundsLike":{"aws:username":"john"}}}}`
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		var pe *policy.ParseError
		if !errors.As(err, &pe) {
			t.Errorf("Parse refused the document with %T (%v), want a *policy.ParseError", err, err)
		}
		return
	}
	r := policy.Evaluate(
		policy.Request{
			Action:    "s3:GetObject",
			Resource:  "*",
			Principal: cfUser,
			Context:   cfCtx{"aws:username": {"john"}},
		},
		p,
	)
	if any(r.Decision) == policy.Allow {
		t.Errorf("unknown operator allowed the request; design requires fail closed")
	}
}

// ---------------------------------------------------------------------------
// Trust policies

// cfTrust is one AllowsPrincipal call; an empty action means sts:AssumeRole.
//
//nolint:govet // fieldalignment: field order reads as the table rows do.
type cfTrust struct {
	name   string
	src    string
	stated string
	action string
	arn    string
	ctx    cfCtx
	want   bool
}

// cfTrustGroup is a trust policy (a testdata/aws file name ending in ".json",
// or the document) and the callers checked against it.
//
//nolint:govet // fieldalignment: field order reads as the table rows do.
type cfTrustGroup struct {
	name  string
	trust string
	cases []cfTrust
}

func cfTrustDoc(principal, extra string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":` + principal + `,"Action":"sts:AssumeRole"}` + extra + `]}`
}

const (
	cfBob     = "arn:aws:iam::123456789012:user/Bob"
	cfRoot    = "arn:aws:iam::123456789012:root"
	cfSession = "arn:aws:sts::123456789012:assumed-role/RoleA/s1"
	cfForeign = "arn:aws:iam::999999999999:user/Bob"
	cfOps     = "arn:aws:iam::444455556666:user/ops"
	cfExtID   = "Unique-ID-Assigned-by-Example-Corp"
)

// Source: docPrincipal "AWS account principals": "The account ARN and the
// shortened account ID behave the same way. Both delegate permissions to the
// account. Using the account ARN ... does not limit permissions to only the
// root user of the account."
var cfAccountTrustCases = []cfTrust{
	{
		name:   "user in account",
		src:    docPrincipal,
		stated: "delegates authority to the account",
		arn:    cfBob,
		want:   true,
	},
	{
		name:   "role session in account",
		src:    docPrincipal,
		stated: "delegates authority to the account",
		arn:    cfSession,
		want:   true,
	},
	{
		name:   "root",
		src:    docPrincipal,
		stated: "account ARN includes the root user",
		arn:    cfRoot,
		want:   true,
	},
	{
		name:   "other account",
		src:    docPrincipal,
		stated: "only the specified account",
		arn:    cfForeign,
		want:   false,
	},
}

// Source: docPrincipal "All principals": `"Principal": "*"` and
// `"Principal" : { "AWS" : "*" }` are equivalent and specify all principals.
var cfEveryoneTrustCases = []cfTrust{
	{name: "user", src: docPrincipal, stated: "all principals", arn: cfBob, want: true},
	{name: "foreign user", src: docPrincipal, stated: "all principals", arn: cfForeign, want: true},
	{name: "session", src: docPrincipal, stated: "all principals", arn: cfSession, want: true},
}

var cfTrustGroups = []cfTrustGroup{
	{"account id", cfTrustDoc(`{"AWS":"123456789012"}`, ""), cfAccountTrustCases},
	{
		"account root ARN",
		cfTrustDoc(`{"AWS":"arn:aws:iam::123456789012:root"}`, ""),
		cfAccountTrustCases,
	},
	// Source: docPrincipal: an array is "a logical OR"; "permissions for the
	// 123456789012 account or the 555555555555 account".
	{
		"account array",
		cfTrustDoc(`{"AWS":["123456789012","555555555555"]}`, ""),
		[]cfTrust{
			{
				name:   "second account",
				src:    docPrincipal,
				stated: "logical OR",
				arn:    "arn:aws:iam::555555555555:user/Ann",
				want:   true,
			},
			{
				name:   "first account",
				src:    docPrincipal,
				stated: "logical OR",
				arn:    cfBob,
				want:   true,
			},
			{
				name:   "neither",
				src:    docPrincipal,
				stated: "only listed accounts",
				arn:    "arn:aws:iam::666666666666:user/Ann",
				want:   false,
			},
		},
	},
	// Source: docPrincipal "IAM user principals": "the user name part of the
	// ARN is case sensitive"; "Principals must always name specific users."
	{
		"user ARN",
		cfTrustDoc(`{"AWS":"arn:aws:iam::123456789012:user/Bob"}`, ""),
		[]cfTrust{
			{
				name:   "that user",
				src:    docPrincipal,
				stated: "names a specific user",
				arn:    cfBob,
				want:   true,
			},
			{
				name:   "case differs",
				src:    docPrincipal,
				stated: "user name part is case sensitive",
				arn:    "arn:aws:iam::123456789012:user/bob",
				want:   false,
			},
			{
				name:   "other user",
				src:    docPrincipal,
				stated: "names a specific user",
				arn:    "arn:aws:iam::123456789012:user/Alice",
				want:   false,
			},
			// ASSUMPTION: naming one user does not admit the account root.
			{
				name:   "root not admitted",
				src:    docPrincipal,
				stated: "ASSUMPTION: a user principal names only that user",
				arn:    cfRoot,
				want:   false,
			},
		},
	},
	// Source: docEvalDenyAll "IAM role": resource policies granting a role ARN
	// "You can specify the role ARN in the Principal element ... the principal
	// that makes the request is the IAM role session."
	{
		"role ARN",
		cfTrustDoc(`{"AWS":"arn:aws:iam::123456789012:role/RoleA"}`, ""),
		[]cfTrust{
			{
				name:   "session of the role",
				src:    docEvalDenyAll,
				stated: "role ARN principal; requester is the role session",
				arn:    cfSession,
				want:   true,
			},
			{
				name:   "session of other role",
				src:    docEvalDenyAll,
				stated: "only that role",
				arn:    "arn:aws:sts::123456789012:assumed-role/RoleB/s1",
				want:   false,
			},
			{name: "user", src: docPrincipal, stated: "only that role", arn: cfBob, want: false},
		},
	},
	// Source: docPrincipal "Role session principals": format
	// arn:aws:sts::AWS-account-ID:assumed-role/role-name/role-session-name.
	{
		"assumed-role session ARN",
		cfTrustDoc(`{"AWS":"arn:aws:sts::123456789012:assumed-role/RoleA/s1"}`, ""),
		[]cfTrust{
			{
				name:   "that session",
				src:    docPrincipal,
				stated: "specifies the role session",
				arn:    cfSession,
				want:   true,
			},
			{
				name:   "other session name",
				src:    docPrincipal,
				stated: "specifies that role session only",
				arn:    "arn:aws:sts::123456789012:assumed-role/RoleA/s2",
				want:   false,
			},
		},
	},
	{"everyone star", cfTrustDoc(`"*"`, ""), cfEveryoneTrustCases},
	{"everyone AWS star", cfTrustDoc(`{"AWS":"*"}`, ""), cfEveryoneTrustCases},
	// Source: docThirdParty: "anyone who wants to assume the role must be a
	// principal in the role and must include the correct external ID."
	{
		"external ID",
		"trust-external-id.json",
		[]cfTrust{
			{
				name:   "correct external id",
				src:    docThirdParty,
				stated: "role ARN and external ID correct: the request succeeds",
				arn:    cfOps,
				ctx:    cfCtx{"sts:ExternalId": {cfExtID}},
				want:   true,
			},
			{
				name:   "session with external id",
				src:    docThirdParty,
				stated: "identities from that account",
				arn:    "arn:aws:sts::444455556666:assumed-role/Ops/s",
				ctx:    cfCtx{"sts:ExternalId": {cfExtID}},
				want:   true,
			},
			{
				name:   "wrong external id",
				src:    docThirdParty,
				stated: "must include the correct external ID",
				arn:    cfOps,
				ctx:    cfCtx{"sts:ExternalId": {"guess"}},
				want:   false,
			},
			{
				name:   "no external id",
				src:    docThirdParty,
				stated: "must include the correct external ID",
				arn:    cfOps,
				want:   false,
			},
			{
				name:   "other account",
				src:    docThirdParty,
				stated: "must be a principal in the role",
				arn:    cfBob,
				ctx:    cfCtx{"sts:ExternalId": {cfExtID}},
				want:   false,
			},
			// ASSUMPTION: Action matching applies to trust statements as elsewhere.
			{
				name:   "other action",
				src:    docAction,
				stated: "ASSUMPTION: statement covers sts:AssumeRole only",
				action: "sts:TagSession",
				arn:    cfOps,
				ctx:    cfCtx{"sts:ExternalId": {cfExtID}},
				want:   false,
			},
		},
	},
	// Source: docPrincipal note on "*": "limit who can access the role through
	// other means, such as a Condition element that limits access to only
	// certain IP addresses."
	{
		"everyone with IP condition",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}}`,
		[]cfTrust{
			{
				name:   "inside",
				src:    docPrincipal,
				stated: "Condition limits access to certain IP addresses",
				arn:    cfForeign,
				ctx:    cfCtx{"aws:SourceIp": {"203.0.113.10"}},
				want:   true,
			},
			{
				name:   "outside",
				src:    docPrincipal,
				stated: "Condition limits access to certain IP addresses",
				arn:    cfForeign,
				ctx:    cfCtx{"aws:SourceIp": {"198.51.100.10"}},
				want:   false,
			},
		},
	},
	// Source: docEvalDenyAll: "An explicit deny overrides an explicit allow."
	{
		"deny statement in trust",
		cfTrustDoc(
			`{"AWS":"123456789012"}`,
			`,{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::123456789012:user/Bob"},"Action":"sts:AssumeRole"}`,
		),
		[]cfTrust{
			{
				name:   "denied user",
				src:    docEvalDenyAll,
				stated: "explicit deny overrides allow",
				arn:    cfBob,
				want:   false,
			},
			{
				name:   "other user",
				src:    docEvalDenyAll,
				stated: "allow from the account",
				arn:    "arn:aws:iam::123456789012:user/Alice",
				want:   true,
			},
		},
	},
	// ASSUMPTION: a Service principal does not admit an IAM user ARN; the
	// service principal "is an identifier for a service" (docPrincipal).
	{
		"service principal",
		cfTrustDoc(`{"Service":"lambda.amazonaws.com"}`, ""),
		[]cfTrust{
			{
				name:   "user not a service",
				src:    docPrincipal,
				stated: "ASSUMPTION: service principal identifies a service",
				arn:    cfBob,
				want:   false,
			},
		},
	},
}

func TestConformanceTrust(t *testing.T) {
	for _, g := range cfTrustGroups {
		t.Run(g.name, func(t *testing.T) {
			trust := cfPolicy(t, g.trust)
			for _, c := range g.cases {
				t.Run(c.name, func(t *testing.T) {
					action := c.action
					if action == "" {
						action = "sts:AssumeRole"
					}
					if got := policy.AllowsPrincipal(trust, action, c.arn, c.ctx); got != c.want {
						t.Errorf(
							"AllowsPrincipal(%s, %s, %v) = %v, want %v\n  source: %s\n  AWS states: %s",
							action,
							c.arn,
							c.ctx,
							got,
							c.want,
							c.src,
							c.stated,
						)
					}
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Robustness

var (
	cfStars = strings.Repeat("a*", 40) + "b"
	cfLong  = strings.Repeat("a", 4000)
)

// ASSUMPTION: the design asks for robustness, AWS gives no time bound. A
// pathological wildcard must be decided well inside 2s (a backtracking matcher
// is exponential in the number of stars on these inputs). None of these
// requests can match (no trailing b), so each must be ImplicitDeny.
//
//nolint:govet // fieldalignment: field order reads as the table rows do.
var cfPathological = []struct {
	name string
	doc  string
	req  policy.Request
}{
	{
		"action",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"svc:` + cfStars + `","Resource":"*"}}`,
		policy.Request{Action: "svc:" + cfLong, Resource: "*", Principal: cfUser},
	},
	{
		"resource",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::` + cfStars + `"}}`,
		policy.Request{
			Action:    "s3:GetObject",
			Resource:  "arn:aws:s3:::" + cfLong,
			Principal: cfUser,
		},
	},
	{
		"resource question marks",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::` + strings.Repeat(
			"?*",
			40,
		) + `b"}}`,
		policy.Request{
			Action:    "s3:GetObject",
			Resource:  "arn:aws:s3:::" + cfLong,
			Principal: cfUser,
		},
	},
	{
		"StringLike",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*","Condition":{"StringLike":{"s3:prefix":"` + cfStars + `"}}}}`,
		policy.Request{
			Action:    "s3:ListBucket",
			Resource:  "*",
			Principal: cfUser,
			Context:   cfCtx{"s3:prefix": {cfLong}},
		},
	},
	{
		"ArnLike",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*","Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:sns:*:*:` + cfStars + `"}}}}`,
		policy.Request{
			Action:    "s3:ListBucket",
			Resource:  "*",
			Principal: cfUser,
			Context:   cfCtx{"aws:SourceArn": {"arn:aws:sns:us-east-1:123456789012:" + cfLong}},
		},
	},
}

func TestConformancePathologicalWildcards(t *testing.T) {
	for _, c := range cfPathological {
		t.Run(c.name, func(t *testing.T) {
			p := cfParse(t, c.doc)
			done := make(chan any, 1)
			go func() { done <- any(policy.Evaluate(c.req, p).Decision) }()
			select {
			case d := <-done:
				if d != policy.ImplicitDeny {
					t.Errorf("Decision = %v, want ImplicitDeny (no trailing b)", d)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Evaluate did not return within 2s")
			}
		})
	}
}

// FuzzConformanceParse checks Parse and Evaluate never panic and Evaluate
// returns one of the three decisions. Seeds are the testdata documents.
func FuzzConformanceParse(f *testing.F) {
	for _, pattern := range []string{"aws/*.json", "malformed/*.json"} {
		files, err := fs.Glob(cfTestdata, pattern)
		if err != nil {
			f.Fatal(err)
		}
		for _, file := range files {
			b, err := fs.ReadFile(cfTestdata, file)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(b, "s3:GetObject", "arn:aws:s3:::b/k")
		}
	}
	f.Fuzz(func(t *testing.T, doc []byte, action, resource string) {
		p, err := policy.Parse(doc)
		if err != nil {
			if p != nil {
				t.Fatalf("Parse returned a policy and an error")
			}
			return
		}
		r := policy.Evaluate(policy.Request{
			Action: action, Resource: resource, Principal: cfUser,
			Context: cfCtx{"aws:username": {"Bob"}, "aws:SourceIp": {"203.0.113.1"}},
		}, p)
		switch any(r.Decision) {
		case policy.Allow, policy.ExplicitDeny, policy.ImplicitDeny:
		default:
			t.Fatalf("Decision %v is none of the three", r.Decision)
		}
		_ = policy.AllowsPrincipal(p, action, cfUser, nil)
	})
}
