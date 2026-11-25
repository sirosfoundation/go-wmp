package jcs

import (
	"errors"
	"math"
	"strconv"
	"testing"
)

// The sample of RFC 8785 section 3.2.2 and its canonical form (section 3.2.4).
func TestCanonicalizeRFC8785Sample(t *testing.T) {
	input := `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := Canonicalize([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// The property sorting example of RFC 8785 section 3.2.3.
func TestCanonicalizeSortsByUTF16CodeUnits(t *testing.T) {
	input := `{
  "\u20ac": "Euro Sign",
  "\r": "Carriage Return",
  "\ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "\ud83d\ude00": "Emoji: Grinning Face",
  "\u0080": "Control",
  "\u00f6": "Latin Small Letter O With Diaeresis"
}`
	want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\"," +
		"\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"
	got, err := Canonicalize([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

// The IEEE 754 samples of RFC 8785 Appendix B.
func TestCanonicalizeNumbersAppendixB(t *testing.T) {
	cases := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	for _, c := range cases {
		text := strconv.FormatFloat(math.Float64frombits(c.bits), 'g', -1, 64)
		got, err := Canonicalize([]byte(text))
		if err != nil {
			t.Fatalf("%x: %v", c.bits, err)
		}
		if string(got) != c.want {
			t.Errorf("%x (%s): got %s, want %s", c.bits, text, got, c.want)
		}
	}
}

func TestCanonicalizeRefuses(t *testing.T) {
	cases := map[string]string{
		"a duplicate member":        `{"a":1,"a":2}`,
		"a nested duplicate member": `{"a":{"b":1,"b":1}}`,
		"trailing data":             `{"a":1}]`,
		"a second value":            `{"a":1} {"b":2}`,
		"a truncated object":        `{"a":1`,
		"a number beyond a double":  `1e400`,
		"invalid UTF-8":             "\"\xff\"",
		"an empty text":             ``,
		"a lone high surrogate":     `"\ud800"`,
		"a lone low surrogate":      `"\udc00"`,
		"a reversed pair":           `"\udc00\ud800"`,
		"a high surrogate and text": `"\ud800x"`,
		"a lone surrogate name":     `{"\ud83d":1}`,
	}
	for name, text := range cases {
		if _, err := Canonicalize([]byte(text)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestMarshalDoesNotEscapeHTML(t *testing.T) {
	got, err := Marshal(map[string]any{"b": "<&>", "a": []int{2, 1}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a":[2,1],"b":"<&>"}`; string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestCanonicalizeAcceptsPairsAndTheReplacementCharacter(t *testing.T) {
	cases := map[string]string{
		`"\ud83d\ude00"`:      "\"\U0001F600\"",
		`"\ufffd"`:            "\"\ufffd\"",
		`"\\ud800"`:           `"\\ud800"`, // an escaped backslash, then text
		`"a\\\\\ud83d\ude00"`: `"a\\\\` + "\U0001F600\"",
	}
	for text, want := range cases {
		got, err := Canonicalize([]byte(text))
		if err != nil || string(got) != want {
			t.Errorf("%s: got %q, %v; want %q", text, got, err, want)
		}
	}
}
