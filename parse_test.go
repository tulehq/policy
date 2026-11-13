package policy

import (
	"errors"
	"strings"
	"testing"
)

func stmt(body string) string {
	return `{"Version":"2012-10-17","Statement":{` + body + `}}`
}

var parseOK = []string{
	// The Version page's example.
	`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}`,
	// Statement as one object, and the 2008 version.
	`{"Version":"2008-10-17","Statement":{"Effect":"Deny","Action":["ec2:*"],"Resource":["*"]}}`,
	// No Version; Id; elements in any order.
	`{"Statement":{"Resource":"*","Action":"*","Effect":"Allow"},"Id":"cd3ad3d9-2776-4ef1-a904-4c229d1642ee"}`,
	// A trust policy has no Resource.
	`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},` +
		`"Action":"sts:AssumeRole"}}`,
	stmt(`"Sid":"1","Effect":"Allow","NotAction":"iam:*","NotResource":"arn:aws:s3:::b"`),
	stmt(
		`"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericLessThan":{"k:n":10},"Bool":{"k:b":true}}`,
	),
	stmt(`"Effect":"Deny","NotPrincipal":{"AWS":"123456789012"},"Action":"s3:*","Resource":"*"`),
	// Unknown operators parse; they never hold.
	stmt(`"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NoSuchOperator":{"k:a":"x"}}`),
}

func TestParseValid(t *testing.T) {
	for _, doc := range parseOK {
		if _, err := Parse([]byte(doc)); err != nil {
			t.Errorf("Parse(%s): %v", doc, err)
		}
	}
}

var parseErrors = []struct{ doc, msg string }{
	{`not json`, msgSyntax},
	{`[]`, msgSyntax},
	{`{"Version":"2012-10-17"}`, msgSyntax},
	{`{"Version":"2012-10-17","Statement":[]}`, msgSyntax},
	{
		`{"Version":"2019-01-01","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		msgSyntax,
	},
	{
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"},"Extra":1}`,
		msgSyntax,
	},
	// "More than one JSON policy object" and "More than one JSON statement
	// element" ("Troubleshoot IAM policies").
	{`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}} {"Statement":{}}`, msgSyntax},
	{`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"},` +
		`"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`, msgSyntax},
	// "More than one effect, action, or resource element".
	{stmt(`"Effect":"Deny","Effect":"Allow","Action":"ec2:*","Resource":"*"`), msgSyntax},
	{stmt(`"Effect":"Allow","Action":"*","Resource":"a","Resource":"b"`), msgSyntax},
	{stmt(`"Effect":"Allow","Action":"*","NotAction":"s3:*","Resource":"*"`), msgSyntax},
	{stmt(`"Effect":"Allow","Action":"*","Resource":"*","NotResource":"*"`), msgSyntax},
	{stmt(`"Effect":"Allow","Action":"*","Resource":"*","Unknown":"x"`), msgSyntax},
	{stmt(`"Effect":"Allow","Action":"*","Resource":"*","Condition":"a"`), msgSyntax},
	{
		stmt(
			`"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"k:a":[]}}}`,
		),
		msgSyntax,
	},
	{
		stmt(
			`"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"k:a":null}}}`,
		),
		msgSyntax,
	},
	{stmt(`"Effect":"Allow","Action":[1],"Resource":"*"`), msgSyntax},
	{stmt(`"Action":"*","Resource":"*"`), msgNoEffect},
	{stmt(`"Effect":"denY","Action":"*","Resource":"*"`), msgLegacy},
	{stmt(`"Effect":"Allow","Resource":"*"`), msgNoActions},
	{stmt(`"Effect":"Allow","Action":[],"Resource":"*"`), msgNoActions},
	{stmt(`"Effect":"Allow","Action":"*"`), msgNoResources},
	{stmt(`"Effect":"Allow","Action":"invalid","Resource":"*"`), msgVendor},
	{stmt(`"Effect":"Allow","Action":"s3:List:Bucket","Resource":"*"`), msgOneColon},
	{stmt(`"Effect":"Allow","Action":"a a:ListBucket","Resource":"*"`), "Vendor a a is not valid"},
	{
		stmt(`"Effect":"Allow","Action":"*","Resource":"invalid resource"`),
		`Resource invalid resource must be in ARN format or "*".`,
	},
	{stmt(`"Effect":"Allow","Action":"*","Resource":"arn:aws"`), msgResourceVendor},
	{stmt(`"Effect":"Allow","Action":"*","Resource":"arn:aws:s*:::b"`), msgResourceVendor},
	{
		`{"Version":"2012-10-17","Statement":[{"Sid":"sdf","Effect":"Allow","Action":"*","Resource":"*"},` +
			`{"Sid":"sdf","Effect":"Deny","Action":"*","Resource":"*"}]}`,
		msgSidUnique,
	},
	{stmt(`"Sid":"has space","Effect":"Allow","Action":"*","Resource":"*"`), msgSidChars},
	{stmt(`"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::*:root"},"Action":"*"`), msgPrincipal},
	{stmt(`"Effect":"Allow","Principal":{"Service":"*"},"Action":"*"`), msgPrincipal},
	{stmt(`"Effect":"Allow","Principal":{"Group":"x"},"Action":"*"`), msgPrincipal},
	{stmt(`"Effect":"Allow","Principal":{},"Action":"*"`), msgPrincipal},
	{
		stmt(`"Effect":"Allow","NotPrincipal":{"AWS":"123456789012"},"Action":"*","Resource":"*"`),
		msgNotPrincipalEff,
	},
	{stmt(`"Effect":"Deny","Principal":"*","NotPrincipal":"*","Action":"*"`), msgSyntax},
	{strings.Repeat("[", 40) + strings.Repeat("]", 40), msgSyntax},
}

func TestParseErrors(t *testing.T) {
	for _, c := range parseErrors {
		_, err := Parse([]byte(c.doc))
		var pe *ParseError
		if !errors.As(err, &pe) {
			t.Errorf("Parse(%s) = %v, want a *ParseError", c.doc, err)
			continue
		}
		if pe.Error() != c.msg {
			t.Errorf("Parse(%s) = %q, want %q", c.doc, pe.Error(), c.msg)
		}
	}
}
