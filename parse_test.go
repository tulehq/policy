package policy

import (
	"errors"
	"strings"
	"testing"
)

// cond is a Deny statement on everything under the Condition element c.
func cond(c string) string {
	return stmt(`"Effect":"Deny","Action":"*","Resource":"*","Condition":` + c)
}

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
	// Variables make Bool and ARN values valid; numbers and booleans may
	// be JSON literals.
	stmt(`"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"k:b":"${k:v}"},` +
		`"ArnLike":{"k:a":"${aws:PrincipalArn}"},"NumericEquals":{"k:n":[1,"2.5","-3e2"]},"Null":{"k:x":true}}`),
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
	{cond(`{"NoSuchOperator":{"k:a":"x"}}`), "Condition operator NoSuchOperator is not valid."},
	{cond(`{"StringNotEqualz":{"k:a":"x"}}`), "Condition operator StringNotEqualz is not valid."},
	{cond(`{"stringequals":{"k:a":"x"}}`), "Condition operator stringequals is not valid."},
	{cond(`{"NullIfExists":{"k:a":"true"}}`), "Condition operator NullIfExists is not valid."},
	{
		cond(`{"ForAnyValue:Null":{"k:a":"true"}}`),
		"Condition operator ForAnyValue:Null is not valid.",
	},
	{
		cond(`{"ForAllValues:StringEqualsIfExist":{"k:a":"x"}}`),
		"Condition operator ForAllValues:StringEqualsIfExist is not valid.",
	},
	{
		cond(`{"ForEachValue:StringEquals":{"k:a":"x"}}`),
		"Condition operator ForEachValue:StringEquals is not valid.",
	},
	{
		cond(`{"NumericNotEquals":{"k:n":"ten"}}`),
		"Condition value ten is not valid for NumericNotEquals.",
	},
	{
		cond(`{"NumericEquals":{"k:n":"${k:m}"}}`),
		"Condition value ${k:m} is not valid for NumericEquals.",
	},
	{
		cond(`{"NumericEquals":{"k:n":"0x10"}}`),
		"Condition value 0x10 is not valid for NumericEquals.",
	},
	{
		cond(`{"DateLessThanIfExists":{"aws:CurrentTime":"soon"}}`),
		"Condition value soon is not valid for DateLessThanIfExists.",
	},
	{
		cond(`{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/33"}}`),
		"Condition value 10.0.0.0/33 is not valid for NotIpAddress.",
	},
	{
		cond(`{"IpAddress":{"aws:SourceIp":["10.0.0.1","nope"]}}`),
		"Condition value nope is not valid for IpAddress.",
	},
	{
		cond(`{"BinaryEquals":{"k:b":"not base64!"}}`),
		"Condition value not base64! is not valid for BinaryEquals.",
	},
	{cond(`{"Bool":{"k:b":"yes"}}`), "Condition value yes is not valid for Bool."},
	{cond(`{"Null":{"k:b":"maybe"}}`), "Condition value maybe is not valid for Null."},
	{
		cond(`{"ForAnyValue:ArnNotLike":{"k:a":"arn:aws:s3"}}`),
		"Condition value arn:aws:s3 is not valid for ForAnyValue:ArnNotLike.",
	},
	// Without Version 2012-10-17 a variable is literal text, so it is no
	// boolean.
	{
		`{"Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Bool":{"k:b":"${k:v}"}}}}`,
		"Condition value ${k:v} is not valid for Bool.",
	},
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
