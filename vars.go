package policy

import "strings"

// Policy variables follow the IAM User Guide, "IAM policy elements:
// Variables and tags"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html):
//
//   - "Variables are marked using a $ prefix followed by a pair of curly
//     braces ({ }) that include the variable name of the value from the
//     request." Names are context keys, so they are case-insensitive.
//   - "${*} - use where you need an * (asterisk) character", "${?}" for a
//     question mark and "${$}" for a dollar sign. They stand for those
//     characters literally, never for wildcards.
//   - "To add a default value to a variable, surround the default value
//     with single quotes (' '), and separate the variable text and the
//     default value with a comma and space (, )."
//   - "Variables were introduced in version 2012-10-17. ... If you don't
//     include the Version element and set it to an appropriate version
//     date, variables like ${aws:username} are treated as literal strings
//     in the policy."
//
// A "${" without a closing "}" is literal text.

// substitute walks raw, passing policy text to text and the value of each
// variable to lit. It returns false when a variable has no value and no
// default. With vars false, all of raw is policy text.
func substitute(raw string, vars bool, c *requestContext, text, lit func(string)) bool {
	if !vars {
		text(raw)
		return true
	}
	for {
		i := strings.Index(raw, "${")
		if i < 0 {
			text(raw)
			return true
		}
		end := strings.IndexByte(raw[i:], '}')
		if end < 0 {
			text(raw)
			return true
		}
		text(raw[:i])
		v, ok := resolve(raw[i+2:i+end], c)
		if !ok {
			return false
		}
		lit(v)
		raw = raw[i+end+1:]
	}
}

// resolve returns the value of the variable named inside ${...}.
func resolve(name string, c *requestContext) (string, bool) {
	switch name {
	case "*", "?", "$":
		return name, true
	}
	key, def, hasDefault := strings.Cut(name, ", '")
	if hasDefault {
		if !strings.HasSuffix(def, "'") {
			key, hasDefault = name, false
		} else {
			def = def[:len(def)-1]
		}
	}
	if v, ok := c.variable(key); ok {
		return v, true
	}
	return def, hasDefault
}

// expand appends raw to p with "*" and "?" as wildcards and each variable's
// value as literal text.
func expand(p pattern, raw string, vars bool, c *requestContext) (pattern, bool) {
	ok := substitute(raw, vars, c,
		func(s string) {
			for _, r := range s {
				p = p.add(globToken(r))
			}
		},
		func(s string) { p = p.literal(s) },
	)
	return p, ok
}

// expandString returns raw with its variables replaced, for the operators
// that take no wildcards.
func expandString(raw string, vars bool, c *requestContext) (string, bool) {
	var b strings.Builder
	ok := substitute(raw, vars, c,
		func(s string) { b.WriteString(s) },
		func(s string) { b.WriteString(s) },
	)
	return b.String(), ok
}
