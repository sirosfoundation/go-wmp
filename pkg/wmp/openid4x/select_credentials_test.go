package openid4x

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const h1 = "Zm9yLXRoZS13YWxsZXQtb25seQ"
const h2 = "b3RoZXItaGFuZGxlLW90aGVyLWhhbmRsZQ"

func sel(q, h string) string { return `{"query_id":"` + q + `","selection_handle":"` + h + `"}` }

func TestParseSelectCredentials(t *testing.T) {
	for name, tc := range map[string]struct {
		in string
		ok bool
	}{
		"consent":                  {`{"consent":true,"selections":[` + sel("pid", h1) + `]}`, true},
		"two queries":              {`{"consent":true,"selections":[` + sel("pid", h1) + `,` + sel("mdl", h1) + `]}`, true},
		"decline":                  {`{"consent":false}`, true},
		"decline empty selections": {`{"consent":false,"selections":[]}`, true},
		"PE descriptor id":         {`{"consent":true,"selections":[` + sel("id:with/odd.chars~", h1) + `]}`, true},
		"consent without":          {`{"consent":true}`, false},
		"consent empty":            {`{"consent":true,"selections":[]}`, false},
		"decline with selections":  {`{"consent":false,"selections":[` + sel("pid", h1) + `]}`, false},
		"consent missing":          {`{"selections":[` + sel("pid", h1) + `]}`, false},
		"consent string":           {`{"consent":"true","selections":[` + sel("pid", h1) + `]}`, false},
		"consent null":             {`{"consent":null}`, false},
		"unknown param":            {`{"consent":false,"note":"x"}`, false},
		"duplicate consent":        {`{"consent":true,"consent":false}`, false},
		"selections null":          {`{"consent":false,"selections":null}`, false},
		"selections object":        {`{"consent":false,"selections":{}}`, false},
		"selection null":           {`{"consent":true,"selections":[null]}`, false},
		"selection credential_id":  {`{"consent":true,"selections":[{"query_id":"pid","selection_handle":"` + h1 + `","credential_id":"c"}]}`, false},
		"old shape":                {`{"consent":true,"selections":[{"credential_id":"c","disclosed_claims":["a"]}]}`, false},
		"missing handle":           {`{"consent":true,"selections":[{"query_id":"pid"}]}`, false},
		"missing query id":         {`{"consent":true,"selections":[{"selection_handle":"` + h1 + `"}]}`, false},
		"duplicate selection key":  {`{"consent":true,"selections":[{"query_id":"a","query_id":"b","selection_handle":"` + h1 + `"}]}`, false},
		"repeated query id":        {`{"consent":true,"selections":[` + sel("pid", h1) + `,` + sel("pid", h1) + `]}`, false},
		"handles differ":           {`{"consent":true,"selections":[` + sel("a", h1) + `,` + sel("b", h2) + `]}`, false},
		"handle short":             {`{"consent":true,"selections":[` + sel("pid", "abc") + `]}`, false},
		"handle padded":            {`{"consent":true,"selections":[` + sel("pid", h1+"==") + `]}`, false},
		"handle trailing newline":  {`{"consent":true,"selections":[` + sel("pid", h1+`\n`) + `]}`, false},
		"handle not string":        {`{"consent":true,"selections":[{"query_id":"pid","selection_handle":7}]}`, false},
		"query id empty":           {`{"consent":true,"selections":[` + sel("", h1) + `]}`, false},
		"query id space":           {`{"consent":true,"selections":[` + sel("my pid", h1) + `]}`, false},
		"query id newline":         {`{"consent":true,"selections":[` + sel(`pid\n`, h1) + `]}`, false},
		"query id nbsp":            {`{"consent":true,"selections":[` + sel(`a\u00a0b`, h1) + `]}`, false},
		"query id zero width":      {`{"consent":true,"selections":[` + sel(`a\u200bb`, h1) + `]}`, false},
		"query id BOM":             {`{"consent":true,"selections":[` + sel(`a\ufeffb`, h1) + `]}`, false},
		"query id C1":              {`{"consent":true,"selections":[` + sel(`a\u0085b`, h1) + `]}`, false},
		"query id too long":        {`{"consent":true,"selections":[` + sel(strings.Repeat("a", 257), h1) + `]}`, false},
		"not an object":            {`[]`, false},
		"empty":                    {``, false},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := ParseSelectCredentials(json.RawMessage(tc.in))
			if tc.ok {
				if err != nil || p == nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !errors.Is(err, ErrSelectCredentials) || p != nil {
				t.Fatalf("accepted or wrong error: %v", err)
			}
		})
	}
}

func TestQueryIDLengthBoundaries(t *testing.T) {
	if !validQueryID(strings.Repeat("a", 256)) || validQueryID(strings.Repeat("a", 257)) {
		t.Error("256 characters is the limit")
	}
	// The limit counts characters, not bytes.
	if !validQueryID(strings.Repeat("é", 256)) {
		t.Error("256 two-byte characters refused")
	}
}

func TestSelectCredentialsErrorsDoNotEchoParams(t *testing.T) {
	for _, in := range []string{
		`{"consent":true,"selections":[{"query_id":"SECRET","selection_handle":"` + h1 + `","SECRET-NAME":"SECRET-VALUE"}]}`,
		`{"consent":true,"selections":[{"query_id":"SECRET VALUE","selection_handle":"` + h1 + `"}]}`,
		`{"consent":true,"selections":[{"query_id":"x","selection_handle":"SECRET-VALUE"}]}`,
		`{"SECRET-NAME":1,"consent":false}`,
	} {
		if _, err := ParseSelectCredentials(json.RawMessage(in)); err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: err = %v", in, err)
		}
	}
}

func TestSelectCredentialsCheck(t *testing.T) {
	p, err := ParseSelectCredentials(json.RawMessage(`{"consent":true,"selections":[` + sel("pid", h1) + `,` + sel("mdl", h1) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"pid", "mdl", "other"}
	if err := p.Check(ids, ""); err != nil {
		t.Errorf("no match handle: %v", err)
	}
	if err := p.Check(ids, h1); err != nil {
		t.Errorf("equal handle: %v", err)
	}
	for name, c := range map[string]struct {
		ids    []string
		handle string
	}{
		"unknown query":        {[]string{"pid"}, ""},
		"handle differs":       {ids, h2},
		"no ids":               {nil, ""},
		"case differs in a id": {[]string{"PID", "mdl"}, ""},
	} {
		err := p.Check(c.ids, c.handle)
		if err == nil || !errors.Is(err, ErrSelectCredentials) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestSignInclusion(t *testing.T) {
	p, _ := ParseSelectCredentials(json.RawMessage(`{"consent":true,"selections":[` + sel("pid", h1) + `,` + sel("mdl", h1) + `]}`))
	refs, handle := p.SignInclusion()
	if len(refs) != 2 || refs[0].CredentialQueryID != "pid" || refs[1].CredentialQueryID != "mdl" || handle != h1 {
		t.Errorf("inclusion = %v %q", refs, handle)
	}
	d, _ := ParseSelectCredentials(json.RawMessage(`{"consent":false}`))
	if refs, handle := d.SignInclusion(); refs != nil || handle != "" {
		t.Errorf("declined inclusion = %v %q", refs, handle)
	}
}

func TestSelectCredentialsParamsMarshalIsTheClosedShape(t *testing.T) {
	b, err := json.Marshal(SelectCredentialsParams{Consent: true, Selections: []QuerySelection{{"pid", h1}}})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"consent":true,"selections":[{"query_id":"pid","selection_handle":"`+h1+`"}]}` {
		t.Errorf("wire = %s", b)
	}
	if _, err := ParseSelectCredentials(b); err != nil {
		t.Errorf("own output refused: %v", err)
	}
	if b, _ := json.Marshal(SelectCredentialsParams{}); string(b) != `{"consent":false}` {
		t.Errorf("decline wire = %s", b)
	}
}
