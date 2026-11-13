package policy

import "unicode"

// tokenKind is one element of a compiled wildcard pattern.
type tokenKind uint8

const (
	// tokLit matches one rune equal to token.r.
	tokLit tokenKind = iota
	// tokAny matches any single rune ("?").
	tokAny
	// tokAnyInSegment matches any single rune except a colon: "?" in one of
	// the first five fields of a Resource ARN.
	tokAnyInSegment
	// tokStar matches any run of runes, including an empty one ("*").
	tokStar
	// tokStarInSegment matches any run of runes without a colon: "*" inside
	// one of the first five fields of a Resource ARN, where it is not the
	// field's last character.
	tokStarInSegment
)

type token struct {
	kind tokenKind
	r    rune
}

// pattern is a compiled wildcard pattern. Policy variables have already been
// replaced by literal tokens, so a "*" that came from a variable's value or
// from the ${*} escape is a literal, not a wildcard.
type pattern []token

// literal appends s to p as literal runes.
func (p pattern) literal(s string) pattern {
	for _, r := range s {
		p = append(p, token{kind: tokLit, r: r})
	}
	return p
}

// add appends t, merging it into a preceding star where the two match the
// same strings, so runs of stars cost one state.
func (p pattern) add(t token) pattern {
	if n := len(p); n > 0 && isStar(t.kind) && isStar(p[n-1].kind) {
		if t.kind == tokStar {
			p[n-1].kind = tokStar
		}
		return p
	}
	return append(p, t)
}

func isStar(k tokenKind) bool { return k == tokStar || k == tokStarInSegment }

// globPattern compiles s with "*" and "?" as wildcards and every other rune
// as a literal. It is the pattern form of Action, NotAction and the
// StringLike operators.
func globPattern(s string) pattern {
	p := make(pattern, 0, len(s))
	for _, r := range s {
		p = p.add(globToken(r))
	}
	return p
}

func globToken(r rune) token {
	switch r {
	case '*':
		return token{kind: tokStar}
	case '?':
		return token{kind: tokAny}
	default:
		return token{kind: tokLit, r: r}
	}
}

// match reports whether p matches all of s. With fold, literals match
// case-insensitively under Unicode simple folding, as strings.EqualFold does.
//
// It simulates the pattern as a nondeterministic automaton whose states are
// the positions in p, so it runs in O(len(p) * len(s)) time and O(len(p))
// space whatever the number of wildcards: a pattern such as "*a*a*a*a*b"
// cannot make it backtrack exponentially.
func (p pattern) match(s string, fold bool) bool {
	cur := make([]bool, len(p)+1)
	next := make([]bool, len(p)+1)
	cur[0] = true
	p.closure(cur)
	for _, c := range s {
		clear(next)
		alive := false
		for i, on := range cur[:len(p)] {
			if !on {
				continue
			}
			if st, adv := p[i].step(c, fold); st || adv {
				next[i] = next[i] || st
				next[i+1] = next[i+1] || adv
				alive = true
			}
		}
		if !alive {
			return false
		}
		p.closure(next)
		cur, next = next, cur
	}
	return cur[len(p)]
}

// closure adds, for every active star, the state after it: a star may match
// the empty string.
func (p pattern) closure(states []bool) {
	for i, t := range p {
		if states[i] && isStar(t.kind) {
			states[i+1] = true
		}
	}
}

// step reports whether the token at a state consumes c and stays (stars) or
// advances to the next state (everything else).
func (t token) step(c rune, fold bool) (stay, advance bool) {
	switch t.kind {
	case tokStar:
		return true, false
	case tokStarInSegment:
		return c != ':', false
	case tokAny:
		return false, true
	case tokAnyInSegment:
		return false, c != ':'
	default:
		return false, c == t.r || fold && equalFold(c, t.r)
	}
}

// equalFold reports whether a and b are equal under Unicode simple folding.
func equalFold(a, b rune) bool {
	for r := unicode.SimpleFold(a); r != a; r = unicode.SimpleFold(r) {
		if r == b {
			return true
		}
	}
	return false
}
