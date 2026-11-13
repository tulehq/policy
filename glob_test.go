package policy

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// regexpOf translates p into an equivalent regular expression. Go's regexp
// guarantees linear-time matching, which makes it an oracle for match.
func regexpOf(p pattern, fold bool) *regexp.Regexp {
	var b strings.Builder
	if fold {
		b.WriteString("(?i)")
	}
	b.WriteString(`(?s)\A`)
	for _, t := range p {
		switch t.kind {
		case tokStar:
			b.WriteString(".*")
		case tokStarInSegment:
			b.WriteString("[^:]*")
		case tokAny:
			b.WriteString(".")
		case tokAnyInSegment:
			b.WriteString("[^:]")
		default:
			b.WriteString(regexp.QuoteMeta(string(t.r)))
		}
	}
	b.WriteString(`\z`)
	return regexp.MustCompile(b.String())
}

var globCases = []struct {
	pattern, s string
	fold, want bool
}{
	{"", "", false, true},
	{"", "a", false, false},
	{"*", "", false, true},
	{"*", "anything:at/all", false, true},
	{"a*", "a", false, true},
	{"a*b", "axxb", false, true},
	{"a*b", "axxbx", false, false},
	{"a?c", "abc", false, true},
	{"a?c", "ac", false, false},
	{"a**b", "ab", false, true},
	{"s3:Get*", "S3:getobject", true, true},
	{"s3:Get*", "S3:getobject", false, false},
	{"*a*a*a*a*a*b", strings.Repeat("a", 64), false, false},
	{"?", "é", false, true},
	{"k", "K", true, true}, // KELVIN SIGN folds to k, as with strings.EqualFold.
}

func TestGlob(t *testing.T) {
	for _, c := range globCases {
		p := globPattern(c.pattern)
		if got := p.match(c.s, c.fold); got != c.want {
			t.Errorf("match(%q, %q, fold=%v) = %v, want %v", c.pattern, c.s, c.fold, got, c.want)
		}
		if got := regexpOf(p, c.fold).MatchString(c.s); got != c.want {
			t.Errorf("oracle(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

var resourceCases = []struct {
	pattern, resource string
	want              bool
}{
	{"*", "arn:aws:s3:::b/k", true},
	// "*" inside a field stays in it; at the end of a field it may span
	// colons ("IAM JSON policy elements: Resource").
	{"arn:aws:sqs:us-*-1:123456789012:q", "arn:aws:sqs:us-east-1:123456789012:q", true},
	{"arn:aws:sqs:us-*-1:123456789012:q", "arn:aws:sqs:us-east:x-1:123456789012:q", false},
	{"arn:aws:sqs:*:123456789012:q", "arn:aws:sqs:us-east-1:x:123456789012:q", true},
	{"arn:aws:sqs:us-east-?:123456789012:q", "arn:aws:sqs:us-east-1:123456789012:q", true},
	{"arn:aws:sqs:us-east?1:123456789012:q", "arn:aws:sqs:us-east:1:123456789012:q", false},
	{
		"arn:aws:lambda:us-east-1:123456789012:function:*",
		"arn:aws:lambda:us-east-1:123456789012:function:f:live",
		true,
	},
	{"arn:aws:s3:::b/*", "arn:aws:s3:::other/k", false},
	{"arn:aws:s3:::b/*", "ARN:aws:s3:::b/k", false},
	{"arn:aws:s3:::b", "arn:aws:s3:::b", true},
	{"arn:aws:s3:::b", "arn:aws:s3:::b/k", false},
	{"arn:aws:s3", "arn:aws:s3:::b/k", true},
	{"arn:aws:s3", "arn:aws:s3x:::b/k", false},
}

func TestResourcePattern(t *testing.T) {
	rc := newRequestContext("", nil)
	for _, c := range resourceCases {
		p, ok := resourcePattern(c.pattern, true, rc)
		if !ok {
			t.Fatalf("resourcePattern(%q) unresolved", c.pattern)
		}
		if got := p.match(c.resource, false); got != c.want {
			t.Errorf("%q matches %q = %v, want %v", c.pattern, c.resource, got, c.want)
		}
	}
}

func TestResourceVariables(t *testing.T) {
	rc := newRequestContext("arn:aws:iam::123456789012:user/a*b", nil)
	p, ok := resourcePattern("arn:aws:s3:::home/${aws:username}/*", true, rc)
	if !ok {
		t.Fatal("aws:username unresolved")
	}
	if !p.match("arn:aws:s3:::home/a*b/k", false) || p.match("arn:aws:s3:::home/axxb/k", false) {
		t.Error("a variable's value must match literally")
	}
	// A variable before the fifth colon stays literal text.
	p, _ = resourcePattern("arn:aws:s3:${aws:username}::b", true, rc)
	if p.match("arn:aws:s3:a*b::b", false) {
		t.Error("a variable outside the resource field must not be replaced")
	}
	if _, ok := resourcePattern("arn:aws:s3:::${aws:PrincipalTag/x}", true, rc); ok {
		t.Error("a variable with no value must leave the entry unresolved")
	}
}

// TestGlobBounded checks that wildcard-heavy patterns cost polynomial
// time: a backtracking matcher takes exponential time on these.
func TestGlobBounded(t *testing.T) {
	p := globPattern(strings.Repeat("*a", 500) + "*b")
	s := strings.Repeat("a", 4000)
	start := time.Now()
	if p.match(s, true) {
		t.Fatal("matched")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("match took %v", d)
	}
}
