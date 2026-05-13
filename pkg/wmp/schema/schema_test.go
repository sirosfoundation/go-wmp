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
