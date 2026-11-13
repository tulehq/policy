package policy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// resourceDoc is a resource-based policy with one statement: effect, the
// principal element (`"Principal":...` or `"NotPrincipal":...`) and the
// rest of the statement.
func resourceDoc(effect, principal, rest string) string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"` + effect + `",` + principal +
		`,"Action":"s3:GetObject"` + rest + `}}`
}

const bucketObjects = `,"Resource":"arn:aws:s3:::b/*"`

var parseResourceCases = []struct {
	name, doc string
	msg       string // the error message, or "" when accepted
}{
	{
		"account principal",
		resourceDoc("Allow", `"Principal":{"AWS":"123456789012"}`, bucketObjects),
		"",
	},
	{"star principal", resourceDoc("Allow", `"Principal":"*"`, bucketObjects), ""},
	{
		"user and role arns",
		resourceDoc("Allow", `"Principal":{"AWS":["arn:aws:iam::123456789012:user/a",`+
			`"arn:aws:iam::123456789012:role/p/r"]}`, bucketObjects),
		"",
	},
	{
		"session arn",
		resourceDoc(
			"Allow",
			`"Principal":{"AWS":"arn:aws:sts::123456789012:assumed-role/r/s"}`,
			bucketObjects,
		),
		"",
	},
	// "IAM identifiers": unique IDs in a resource-based Principal.
	{
		"unique ids",
		resourceDoc(
			"Allow",
			`"Principal":{"AWS":["AIDACKCEVSQ6C2EXAMPLE","AROADBQP57FF2AEXAMPLE"]}`,
			bucketObjects,
		),
		"",
	},
	{
		"service principal",
		resourceDoc("Allow", `"Principal":{"Service":"sns.amazonaws.com"}`, bucketObjects),
		"",
	},
	{
		"canonical user",
		resourceDoc(
			"Allow",
			`"Principal":{"CanonicalUser":"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"}`,
			bucketObjects,
		),
		"",
	},
	{
		"NotPrincipal deny",
		resourceDoc("Deny", `"NotPrincipal":{"AWS":"123456789012"}`, bucketObjects),
		"",
	},
	{
		"NotResource",
		resourceDoc("Allow", `"Principal":"*"`, `,"NotResource":"arn:aws:s3:::b/k"`),
		"",
	},
	{
		"no principal",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		msgNoPrincipal,
	},
	{
		"no principal, no resource",
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*"}}`,
		msgNoPrincipal,
	},
	{"no resource", resourceDoc("Allow", `"Principal":"*"`, ""), msgNoResources},
	{
		"NotPrincipal allow",
		resourceDoc("Allow", `"NotPrincipal":{"AWS":"123456789012"}`, bucketObjects),
		msgNotPrincipalEff,
	},
	// "OIDC federated principals are not supported in policy types other
	// than role trust policies."
	{
		"federated oidc",
		resourceDoc("Allow", `"Principal":{"Federated":"accounts.google.com"}`, bucketObjects),
		msgPrincipal,
	},
	{
		"federated saml",
		resourceDoc(
			"Allow",
			`"Principal":{"Federated":"arn:aws:iam::123456789012:saml-provider/p"}`,
			bucketObjects,
		),
		msgPrincipal,
	},
	{
		"unique id lower case",
		resourceDoc("Allow", `"Principal":{"AWS":"AIDAckcevsq6c2example"}`, bucketObjects),
		msgPrincipal,
	},
	{
		"unique id too short",
		resourceDoc("Allow", `"Principal":{"AWS":"AIDA123"}`, bucketObjects),
		msgPrincipal,
	},
	{
		"group unique id",
		resourceDoc("Allow", `"Principal":{"AWS":"AGPACKCEVSQ6C2EXAMPLE"}`, bucketObjects),
		msgPrincipal,
	},
	{
		"unique id as service",
		resourceDoc("Allow", `"Principal":{"Service":"AIDACKCEVSQ6C2EXAMPLE"}`, bucketObjects),
		msgPrincipal,
	},
	{
		"partial wildcard",
		resourceDoc(
			"Allow",
			`"Principal":{"AWS":"arn:aws:iam::123456789012:user/*"}`,
			bucketObjects,
		),
		msgPrincipal,
	},
	{
		"one statement lacks a principal", `{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"},` +
			`{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
		msgNoPrincipal,
	},
	{"malformed", `{"Statement":[]}`, msgSyntax},
}

func TestParseResource(t *testing.T) {
	for _, c := range parseResourceCases {
		t.Run(c.name, func(t *testing.T) {
			p, err := ParseResource([]byte(c.doc))
			if c.msg == "" {
				if err != nil || p == nil {
					t.Fatalf("ParseResource: %v, want accepted", err)
				}
				return
			}
			var pe *ParseError
			if !errors.As(err, &pe) || pe.Message != c.msg || p != nil {
				t.Fatalf("ParseResource: %v, want %q", err, c.msg)
			}
		})
	}
}

// Unique IDs are accepted only in resource-based policies; the other kinds
// are unchanged.
func TestUniqueIDsOnlyInResourcePolicies(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
		`"Principal":{"AWS":"AIDACKCEVSQ6C2EXAMPLE"},"Action":"sts:AssumeRole"}}`
	for name, parse := range map[string]func([]byte) (*Policy, error){"Parse": Parse, "ParseTrust": ParseTrust} {
		var pe *ParseError
		if _, err := parse([]byte(doc)); !errors.As(err, &pe) || pe.Message != msgPrincipal {
			t.Errorf("%s: %v, want %q", name, err, msgPrincipal)
		}
	}
}

// A resource-based policy's Sid follows its service's rule, not IAM's
// alphanumeric one: SQS AddPermission labels and Lambda statement IDs take
// hyphens and underscores. The other kinds keep IAM's rule, and a Sid stays
// unique within any policy.
func TestResourcePolicySidsAreTheServices(t *testing.T) {
	doc := func(sids ...string) []byte {
		var b strings.Builder
		b.WriteString(`{"Version":"2012-10-17","Statement":[`)
		for i, sid := range sids {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"Sid":%q,"Effect":"Allow","Principal":{"AWS":"123456789012"},`+
				`"Action":"sqs:SendMessage","Resource":"*"}`, sid)
		}
		b.WriteString("]}")
		return []byte(b.String())
	}
	for _, sid := range []string{"Queue1_SendMessage", "my-label", "lambda-invoke_1", "has space"} {
		p, err := ParseResource(doc(sid))
		if err != nil || p == nil {
			t.Fatalf("ParseResource with Sid %q: %v, want accepted", sid, err)
		}
	}
	var pe *ParseError
	if _, err := ParseResource(doc("a-b", "a-b")); !errors.As(err, &pe) {
		t.Fatalf("ParseResource with a repeated Sid: %v, want refused", err)
	}
}

// The identity and trust kinds keep IAM's alphanumeric Sid rule.
func TestIdentityAndTrustSidsStayAlphanumeric(t *testing.T) {
	var pe *ParseError
	identity := []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"a-b","Effect":"Allow",` +
		`"Action":"s3:GetObject","Resource":"*"}]}`)
	if _, err := ParseIdentity(identity); !errors.As(err, &pe) || pe.Message != msgSidChars {
		t.Fatalf("ParseIdentity with Sid a-b: %v, want %q", err, msgSidChars)
	}
	trust := []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"a_b","Effect":"Allow",` +
		`"Principal":{"AWS":"123456789012"},"Action":"sts:AssumeRole"}]}`)
	if _, err := ParseTrust(trust); !errors.As(err, &pe) || pe.Message != msgSidChars {
		t.Fatalf("ParseTrust with Sid a_b: %v, want %q", err, msgSidChars)
	}
}
