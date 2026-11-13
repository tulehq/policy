package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// member is one name/value pair of a JSON object, in document order.
type member struct {
	value any
	name  string
}

// object is a decoded JSON object. The values of an object, an array, a
// string, a number, a boolean and null decode to object, []any, string,
// json.Number, bool and nil.
type object []member

// maxDepth bounds nesting. A policy nests five levels (policy, statement,
// condition operator, condition key, value list); anything deeper is not a
// policy, and the bound caps the decoder's recursion.
const maxDepth = 16

var errSyntax = errors.New("syntax")

// decodeJSON decodes exactly one JSON value from doc. Unlike
// encoding/json.Unmarshal it rejects an object that repeats a name:
// "Individual elements must not contain multiple instances of the same key."
// (IAM User Guide, "Grammar of the IAM JSON policy language", policy
// grammar notes,
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html).
// It also rejects anything after the value, such as a second policy object
// ("An IAM policy must consist of only one JSON object."; IAM User Guide,
// "Troubleshoot IAM policies",
// https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_policies.html).
func decodeJSON(doc []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errSyntax
	}
	return v, nil
}

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errSyntax
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, errSyntax
	}
	switch tok {
	case json.Delim('{'):
		return decodeObject(dec, depth)
	case json.Delim('['):
		return decodeArray(dec, depth)
	default:
		return tok, nil
	}
}

func decodeObject(dec *json.Decoder, depth int) (object, error) {
	obj := object{}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errSyntax
		}
		name, _ := tok.(string)
		if seen[name] {
			return nil, errSyntax
		}
		seen[name] = true
		v, err := decodeValue(dec, depth+1)
		if err != nil {
			return nil, err
		}
		obj = append(obj, member{name: name, value: v})
	}
	if _, err := dec.Token(); err != nil {
		return nil, errSyntax
	}
	return obj, nil
}

func decodeArray(dec *json.Decoder, depth int) ([]any, error) {
	arr := []any{}
	for dec.More() {
		v, err := decodeValue(dec, depth+1)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
	}
	if _, err := dec.Token(); err != nil {
		return nil, errSyntax
	}
	return arr, nil
}
