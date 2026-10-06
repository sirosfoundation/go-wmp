package schema

import (
	"encoding/json"
	"testing"
)

func TestNewValidator(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}
	if v == nil {
		t.Fatal("validator is nil")
	}
}

func TestValidateSessionCreate(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	// Valid session.create request.
	valid := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "wmp.session.create",
		"params": map[string]interface{}{
			"wmp": map[string]interface{}{
				"version": "0.1",
			},
		},
	}
	data, _ := json.Marshal(valid)
	if err := v.ValidateMethod("wmp.session.create", data); err != nil {
		t.Errorf("valid message failed: %v", err)
	}

	// Invalid: missing params.
	invalid := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "wmp.session.create",
	}
	data, _ = json.Marshal(invalid)
	if err := v.ValidateMethod("wmp.session.create", data); err == nil {
		t.Error("expected error for missing params")
	}
}

func TestValidateFlowStart(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	valid := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "flow-1",
		"method":  "wmp.flow.start",
		"params": map[string]interface{}{
			"wmp":       map[string]interface{}{"version": "0.1"},
			"flow_type": "oid4vci",
			"flow_id":   "f-001",
		},
	}
	data, _ := json.Marshal(valid)
	if err := v.ValidateMethod("wmp.flow.start", data); err != nil {
		t.Errorf("valid flow.start failed: %v", err)
	}

	// Missing flow_type.
	invalid := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "flow-1",
		"method":  "wmp.flow.start",
		"params": map[string]interface{}{
			"wmp":     map[string]interface{}{"version": "0.1"},
			"flow_id": "f-001",
		},
	}
	data, _ = json.Marshal(invalid)
	if err := v.ValidateMethod("wmp.flow.start", data); err == nil {
		t.Error("expected error for missing flow_type")
	}
}

func TestValidateFlowProgress(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	valid := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "wmp.flow.progress",
		"params": map[string]interface{}{
			"wmp":     map[string]interface{}{"version": "0.1"},
			"flow_id": "f-001",
			"step":    "metadata_fetched",
			"payload": map[string]interface{}{
				"issuer_metadata": map[string]interface{}{},
			},
		},
	}
	data, _ := json.Marshal(valid)
	if err := v.ValidateMethod("wmp.flow.progress", data); err != nil {
		t.Errorf("valid flow.progress failed: %v", err)
	}
}

func TestValidateResolve(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	valid := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "r-1",
		"method":  "wmp.resolve",
		"params": map[string]interface{}{
			"wmp":  map[string]interface{}{"version": "0.1"},
			"type": "vctm",
			"uri":  "https://example.com/vctm/pid",
		},
	}
	data, _ := json.Marshal(valid)
	if err := v.ValidateMethod("wmp.resolve", data); err != nil {
		t.Errorf("valid resolve failed: %v", err)
	}
}

func TestValidateUnknownMethod(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	// Unknown method should pass (no schema).
	data := []byte(`{"jsonrpc":"2.0","method":"unknown","id":1}`)
	if err := v.ValidateMethod("unknown", data); err != nil {
		t.Errorf("unknown method should not error: %v", err)
	}
}

func TestMethodSchemas(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	methods := v.MethodSchemas()
	if len(methods) == 0 {
		t.Error("expected at least one method schema")
	}

	// Should include key methods.
	found := make(map[string]bool)
	for _, m := range methods {
		found[m] = true
	}
	for _, want := range []string{"wmp.session.create", "wmp.flow.start", "wmp.resolve"} {
		if !found[want] {
			t.Errorf("missing method schema for %s", want)
		}
	}
}

func TestValidateSessionCreateResponse(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	valid := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]interface{}{
			"wmp": map[string]interface{}{
				"version": "0.1",
			},
			"capabilities": map[string]interface{}{},
		},
	}
	data, _ := json.Marshal(valid)
	if err := v.ValidateResponse("wmp.session.create", data); err != nil {
		t.Errorf("valid response failed: %v", err)
	}
}

func TestWithStrict(t *testing.T) {
	v, err := NewValidator(WithStrict(true))
	if err != nil {
		t.Fatalf("NewValidator error: %v", err)
	}

	if err := v.ValidateMethod("unknown.method", []byte(`{}`)); err == nil {
		t.Error("expected error for unknown method in strict mode")
	}
	if err := v.ValidateResponse("unknown.method", []byte(`{}`)); err == nil {
		t.Error("expected error for unknown response in strict mode")
	}
}

func TestValidateMetadata(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator error: %v", err)
	}
	valid := map[string]interface{}{
		"version": "0.1",
	}
	data, _ := json.Marshal(valid)
	if err := v.ValidateMetadata(data); err != nil {
		t.Errorf("valid metadata failed: %v", err)
	}

	if err := v.ValidateMetadata([]byte(`{`)); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestSchemaCaching(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator error: %v", err)
	}
	data := []byte(`{"jsonrpc":"2.0","id":1,"method":"wmp.session.create","params":{"wmp":{"version":"0.1"}}}`)
	if err := v.ValidateMethod("wmp.session.create", data); err != nil {
		t.Fatalf("first validation failed: %v", err)
	}
	if err := v.ValidateMethod("wmp.session.create", data); err != nil {
		t.Fatalf("second validation (cached) failed: %v", err)
	}
}

func sessionCreateWithCaps(t *testing.T, caps map[string]interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "wmp.session.create",
		"params": map[string]interface{}{
			"wmp":                  map[string]interface{}{"version": "0.1"},
			"capabilities_offered": caps,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The transaction_data capability (OpenID4x profile, Section 2.3) is defined,
// not just tolerated through the generic custom-capability fallback: a typo in
// a member name or a version of 0 is rejected.
func TestValidateTransactionDataCapability(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		caps  map[string]interface{}
		valid bool
	}{
		{"version 1", map[string]interface{}{"transaction_data": map[string]interface{}{"versions": []int{1}}}, true},
		{"with hash algs", map[string]interface{}{"transaction_data": map[string]interface{}{"versions": []int{1}, "hash_algs": []string{"sha-256"}}}, true},
		{"no versions", map[string]interface{}{"transaction_data": map[string]interface{}{}}, false},
		{"empty versions", map[string]interface{}{"transaction_data": map[string]interface{}{"versions": []int{}}}, false},
		{"version zero", map[string]interface{}{"transaction_data": map[string]interface{}{"versions": []int{0}}}, false},
		{"unknown member", map[string]interface{}{"transaction_data": map[string]interface{}{"versions": []int{1}, "hash_alg": "sha-256"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := v.ValidateMethod("wmp.session.create", sessionCreateWithCaps(t, c.caps))
			if c.valid && err != nil {
				t.Fatalf("want valid, got %v", err)
			}
			if !c.valid && err == nil {
				t.Fatal("want invalid, got nil")
			}
		})
	}
}
