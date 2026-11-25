// Package jcs implements the JSON Canonicalization Scheme (RFC 8785), the
// form WMP signs and hashes content objects in (WMP Core section 5.4).
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrInvalid is wrapped by every error of a JSON text that has no canonical
// form: malformed JSON, a duplicate member name, invalid UTF-8, a lone
// surrogate or a number outside the IEEE 754 double range.
var ErrInvalid = errors.New("jcs: no canonical form")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// maxDepth bounds the nesting of a canonicalized text.
const maxDepth = 512

// Canonicalize returns the RFC 8785 form of a JSON text.
func Canonicalize(text []byte) ([]byte, error) {
	if !utf8.Valid(text) {
		return nil, invalid("not UTF-8")
	}
	if err := checkSurrogates(text); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	out, err := appendValue(nil, dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, invalid("data after the JSON value")
	}
	return out, nil
}

// Marshal returns the RFC 8785 form of the JSON encoding of v.
func Marshal(v any) ([]byte, error) {
	text, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonicalize(text)
}

// checkSurrogates refuses a \u escape of a surrogate that is not half of a
// pair. encoding/json would decode it to U+FFFD, which RFC 8785 does not
// allow: a lone surrogate has no canonical form. A backslash occurs only
// inside a JSON string, so the whole text can be scanned for escapes.
func checkSurrogates(text []byte) error {
	for i := 0; i < len(text); i++ {
		if text[i] != '\\' {
			continue
		}
		unit, ok := escapedUnit(text, i)
		if !ok {
			i++ // a two-character escape, or malformed JSON the decoder refuses
			continue
		}
		i += 5
		if !utf16.IsSurrogate(rune(unit)) {
			continue
		}
		low, ok := escapedUnit(text, i+1)
		if unit >= 0xdc00 || !ok || low < 0xdc00 || low > 0xdfff {
			return invalid("a lone surrogate")
		}
		i += 6
	}
	return nil
}

// escapedUnit returns the code unit of a \uXXXX escape that starts at text[i].
func escapedUnit(text []byte, i int) (uint16, bool) {
	if i+6 > len(text) || text[i] != '\\' || text[i+1] != 'u' {
		return 0, false
	}
	v, err := strconv.ParseUint(string(text[i+2:i+6]), 16, 16)
	return uint16(v), err == nil
}

func appendValue(b []byte, dec *json.Decoder, depth int) ([]byte, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, invalid("%v", err)
	}
	return appendToken(b, dec, tok, depth)
}

func appendToken(b []byte, dec *json.Decoder, tok json.Token, depth int) ([]byte, error) {
	switch t := tok.(type) {
	case nil:
		return append(b, "null"...), nil
	case bool:
		return strconv.AppendBool(b, t), nil
	case string:
		return appendString(b, t)
	case json.Number:
		return appendNumber(b, t)
	case json.Delim:
		if depth >= maxDepth {
			return nil, invalid("nested deeper than %d", maxDepth)
		}
		if t == '[' {
			return appendArray(b, dec, depth+1)
		}
		if t == '{' {
			return appendObject(b, dec, depth+1)
		}
	}
	return nil, invalid("unexpected token %v", tok)
}

func appendArray(b []byte, dec *json.Decoder, depth int) ([]byte, error) {
	b = append(b, '[')
	for first := true; dec.More(); first = false {
		if !first {
			b = append(b, ',')
		}
		var err error
		if b, err = appendValue(b, dec, depth); err != nil {
			return nil, err
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, invalid("%v", err)
	}
	return append(b, ']'), nil
}

type member struct {
	name  string
	key   []uint16
	value []byte
}

func appendObject(b []byte, dec *json.Decoder, depth int) ([]byte, error) {
	var members []member
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, invalid("%v", err)
		}
		name, ok := tok.(string)
		if !ok {
			return nil, invalid("a member name is not a string")
		}
		if seen[name] {
			return nil, invalid("duplicate member %q", name)
		}
		seen[name] = true
		value, err := appendValue(nil, dec, depth)
		if err != nil {
			return nil, err
		}
		members = append(members, member{name: name, key: utf16.Encode([]rune(name)), value: value})
	}
	if _, err := dec.Token(); err != nil {
		return nil, invalid("%v", err)
	}
	// RFC 8785 section 3.2.3: member names sort by their UTF-16 code units.
	sort.Slice(members, func(i, j int) bool { return lessUTF16(members[i].key, members[j].key) })
	b = append(b, '{')
	for i, m := range members {
		if i > 0 {
			b = append(b, ',')
		}
		var err error
		if b, err = appendString(b, m.name); err != nil {
			return nil, err
		}
		b = append(b, ':')
		b = append(b, m.value...)
	}
	return append(b, '}'), nil
}

func lessUTF16(a, b []uint16) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// appendString appends s in the RFC 8785 form: only the quote, the backslash
// and the C0 controls are escaped.
func appendString(b []byte, s string) ([]byte, error) {
	const hexDigits = "0123456789abcdef"
	if !utf8.ValidString(s) {
		return nil, invalid("a string is not UTF-8")
	}
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b = append(b, '\\', c)
		case c == '\b':
			b = append(b, '\\', 'b')
		case c == '\t':
			b = append(b, '\\', 't')
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\f':
			b = append(b, '\\', 'f')
		case c == '\r':
			b = append(b, '\\', 'r')
		case c < 0x20:
			b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		default:
			b = append(b, c)
		}
	}
	return append(b, '"'), nil
}

// appendNumber appends n as ECMAScript's Number::toString does (RFC 8785
// section 3.2.2.3).
func appendNumber(b []byte, n json.Number) ([]byte, error) {
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, invalid("number %s is outside the double range", n)
	}
	if f == 0 {
		return append(b, '0'), nil
	}
	if f < 0 {
		b = append(b, '-')
		f = -f
	}
	// The shortest digits that round-trip, as d.ddde±xx.
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, exponent, _ := strings.Cut(sci, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exp, _ := strconv.Atoi(exponent)
	k, pos := len(digits), exp+1 // the decimal point sits after digit `pos`

	switch {
	case k <= pos && pos <= 21:
		b = append(b, digits...)
		b = append(b, strings.Repeat("0", pos-k)...)
	case 0 < pos && pos <= 21:
		b = append(b, digits[:pos]...)
		b = append(b, '.')
		b = append(b, digits[pos:]...)
	case -6 < pos && pos <= 0:
		b = append(b, "0."...)
		b = append(b, strings.Repeat("0", -pos)...)
		b = append(b, digits...)
	default:
		b = append(b, digits[0])
		if k > 1 {
			b = append(b, '.')
			b = append(b, digits[1:]...)
		}
		b = append(b, 'e')
		if exp >= 0 {
			b = append(b, '+')
		}
		b = strconv.AppendInt(b, int64(exp), 10)
	}
	return b, nil
}
