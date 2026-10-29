package wmp

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestProjectVCTMKeepsDisplayedMembersOnly(t *testing.T) {
	doc := `{"vct":"https://c.example/id","name":"N","description":"D","display":[{"lang":"en"}],
	  "claims":[{"path":["a"]}],"schema":{"type":"object"},"extends":"https://c.example/base","svg_templates":[1]}`
	got, err := ProjectVCTM([]byte(doc), "https://other.example/uri")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"vct", "name", "description", "display", "claims", "schema"} {
		if _, ok := m[k]; !ok {
			t.Errorf("member %q missing from %s", k, got)
		}
	}
	for _, k := range []string{"extends", "svg_templates"} {
		if _, ok := m[k]; ok {
			t.Errorf("member %q must be dropped: %s", k, got)
		}
	}
	if string(m["vct"]) != `"https://c.example/id"` {
		t.Errorf("document vct must win over uri: %s", m["vct"])
	}
	if string(m["claims"]) != `[{"path":["a"]}]` {
		t.Errorf("claims not verbatim: %s", m["claims"])
	}
}

func TestProjectVCTMDefaultsVCTToURI(t *testing.T) {
	for _, doc := range []string{`{"name":"N"}`, `{"vct":"","name":"N"}`, `{"vct":null}`} {
		got, err := ProjectVCTM([]byte(doc), "https://c.example/id")
		if err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
		var raw map[string]any
		_ = json.Unmarshal(got, &raw)
		vct, _ := raw["vct"].(string)
		if vct != "https://c.example/id" {
			t.Errorf("%s: vct = %q", doc, vct)
		}
	}
}

func TestProjectVCTMRefusesNonObjects(t *testing.T) {
	for _, doc := range []string{`[]`, `"x"`, `null`, `42`, `{"vct":7}`, ``, `{`,
		// name and description are strings, or the metadata would fail its own schema
		`{"vct":"v","name":42}`, `{"vct":"v","description":{}}`, `{"vct":"v","name":["n"]}`} {
		if _, err := ProjectVCTM([]byte(doc), "https://c.example/id"); !errors.Is(err, ErrVCTMNotObject) {
			t.Errorf("%q: err = %v, want ErrVCTMNotObject", doc, err)
		}
	}
	if _, err := ProjectVCTM([]byte(`{"name":"N"}`), ""); err == nil {
		t.Error("no vct and no uri must be refused")
	}
}

func TestNewVCTMResolveResultShape(t *testing.T) {
	res, err := NewVCTMResolveResult("ses-1", "https://c.example/id", []byte(`{"vct":"https://c.example/id","name":"N"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	if _, ok := m["body"]; ok {
		t.Error("result must not carry body")
	}
	if _, ok := m["content_type"]; ok {
		t.Error("result must not carry content_type")
	}
	if string(m["metadata"]) != `{"vct":"https://c.example/id","name":"N"}` {
		t.Errorf("metadata = %s", m["metadata"])
	}
	if res.WMP.SessionID != "ses-1" || res.WMP.Version != Version || res.Type != ResolveTypeVCTM {
		t.Errorf("result = %+v", res)
	}
	if _, err := NewVCTMResolveResult("s", "u", []byte(`[]`)); err == nil {
		t.Error("a non-object document must be an error")
	}
}

func TestNewUnknownResolveResultIsNull(t *testing.T) {
	b, _ := json.Marshal(NewUnknownResolveResult("ses-1", ResolveTypeVCTM, "https://c.example/x"))
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	if v, ok := m["metadata"]; !ok || string(v) != "null" {
		t.Errorf("metadata = %s (present %v), want null", v, ok)
	}
}

func TestMetadataFetchErrorAndParams(t *testing.T) {
	e := NewMetadataFetchError()
	if e.Code != ErrInternalError || string(e.Data) != `{"reason":"metadata_fetch_error"}` {
		t.Errorf("error = %d %s", e.Code, e.Data)
	}
	if ValidateVCTMResolveParams(&ResolveParams{Type: ResolveTypeVCTM, URI: "https://c.example/id"}) != nil {
		t.Error("valid params refused")
	}
	for _, p := range []*ResolveParams{nil, {Type: ResolveTypeVCTM}, {Type: "endpoint", URI: "x"}} {
		if e := ValidateVCTMResolveParams(p); e == nil || e.Code != ErrInvalidParams {
			t.Errorf("%+v: %v", p, e)
		}
	}
}

func TestProjectVCTMNullMembers(t *testing.T) {
	got, err := ProjectVCTM([]byte(`{"vct":"v","name":null,"description":null,"display":null,"claims":null,"schema":null}`), "u")
	if err != nil {
		t.Fatal(err)
	}
	// display, claims and schema are carried verbatim, null included; a null name
	// or description is absent.
	if string(got) != `{"vct":"v","display":null,"claims":null,"schema":null}` {
		t.Errorf("projection = %s", got)
	}
}
