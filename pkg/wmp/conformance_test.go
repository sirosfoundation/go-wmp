package wmp_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// TestVector is the schema for a single WMP conformance test vector.
type TestVector struct {
	ID               string          `json:"id"`
	Description      string          `json:"description"`
	ConformanceLevel string          `json:"conformance_level"`
	Input            json.RawMessage `json:"input"`
	ExpectedResponse json.RawMessage `json:"expected_response,omitempty"`
	ExpectedError    json.RawMessage `json:"expected_error,omitempty"`
	Notes            string          `json:"notes,omitempty"`
}

// genericRPC is a loosely-typed JSON-RPC message for structural validation.
type genericRPC struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// vectorsDir returns the path to the wmp/vectors/ directory.
func vectorsDir() string {
	_, file, _, _ := runtime.Caller(0)
	// go-wmp/pkg/wmp/conformance_test.go → ../../wmp/vectors/
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "wmp", "vectors")
}

func loadVectors(t *testing.T, filename string) []TestVector {
	t.Helper()
	path := filepath.Join(vectorsDir(), filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", path, err)
	}
	var vectors []TestVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse %s: %v", filename, err)
	}
	return vectors
}

// knownMethods returns the set of all WMP method constants.
func knownMethods() map[string]bool {
	return map[string]bool{
		wmp.MethodSessionCreate:       true,
		wmp.MethodSessionResume:       true,
		wmp.MethodSessionClose:        true,
		wmp.MethodSessionAuthenticate: true,
		wmp.MethodMessageDeliver:      true,
		wmp.MethodMessageAck:          true,
		wmp.MethodMessagePoll:         true,
		wmp.MethodMessageStatus:       true,
		wmp.MethodCapabilityUpdate:    true,
		wmp.MethodCapabilityList:      true,
		wmp.MethodFlowStart:          true,
		wmp.MethodFlowProgress:       true,
		wmp.MethodFlowAction:         true,
		wmp.MethodFlowComplete:       true,
		wmp.MethodFlowError:          true,
		wmp.MethodFlowCancel:         true,
		wmp.MethodResolve:            true,
		wmp.MethodRelayRegister:      true,
	}
}

// knownErrors returns the set of all WMP + JSON-RPC error codes.
func knownErrors() map[int]bool {
	return map[int]bool{
		wmp.ErrParseError:               true,
		wmp.ErrInvalidRequest:           true,
		wmp.ErrMethodNotFound:           true,
		wmp.ErrInvalidParams:            true,
		wmp.ErrInternalError:            true,
		wmp.ErrSessionNotFound:          true,
		wmp.ErrSessionExpired:           true,
		wmp.ErrNotAuthorized:            true,
		wmp.ErrEncryptionRequired:       true,
		wmp.ErrMLSError:                 true,
		wmp.ErrCapabilityNotSupported:   true,
		wmp.ErrFlowError:                true,
		wmp.ErrRateLimited:              true,
		wmp.ErrParticipantNotFound:      true,
		wmp.ErrEvidenceRequired:         true,
		wmp.ErrSignatureInvalid:         true,
		wmp.ErrTimestampInvalid:         true,
		wmp.ErrIdentityAssertionInvalid: true,
		wmp.ErrVersionNotSupported:      true,
		wmp.ErrQueueFull:                true,
	}
}

// assertValidRequest verifies structural validity of a JSON-RPC request.
func assertValidRequest(t *testing.T, raw json.RawMessage, vectorID string) {
	t.Helper()
	var msg genericRPC
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("%s: failed to parse input: %v", vectorID, err)
	}

	if msg.JSONRPC != "2.0" {
		t.Errorf("%s: jsonrpc = %q, want 2.0", vectorID, msg.JSONRPC)
	}
	if msg.Method == "" {
		t.Errorf("%s: method must not be empty", vectorID)
	}

	methods := knownMethods()
	if !methods[msg.Method] {
		// Some vectors deliberately use unknown methods (error-method-not-found)
		return
	}

	// Verify params.wmp exists for known methods
	if len(msg.Params) > 0 {
		var params map[string]json.RawMessage
		if err := json.Unmarshal(msg.Params, &params); err == nil {
			if _, ok := params["wmp"]; !ok {
				t.Errorf("%s: params.wmp must exist for method %s", vectorID, msg.Method)
			}
		}
	}
}

// assertValidResponse verifies structural validity of a JSON-RPC response.
func assertValidResponse(t *testing.T, raw json.RawMessage, vectorID string) {
	t.Helper()
	var msg genericRPC
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("%s: failed to parse response: %v", vectorID, err)
	}

	if msg.JSONRPC != "2.0" {
		t.Errorf("%s: response jsonrpc = %q, want 2.0", vectorID, msg.JSONRPC)
	}

	if len(msg.Result) > 0 {
		var result map[string]json.RawMessage
		if err := json.Unmarshal(msg.Result, &result); err == nil {
			if _, ok := result["wmp"]; !ok {
				t.Errorf("%s: result.wmp must exist", vectorID)
			}
		}
	}
}

// assertValidError verifies structural validity of a JSON-RPC error response.
func assertValidError(t *testing.T, raw json.RawMessage, vectorID string) {
	t.Helper()
	var msg genericRPC
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("%s: failed to parse error response: %v", vectorID, err)
	}

	if msg.JSONRPC != "2.0" {
		t.Errorf("%s: error response jsonrpc = %q, want 2.0", vectorID, msg.JSONRPC)
	}
	if msg.Error == nil {
		t.Fatalf("%s: error field must exist", vectorID)
	}
	if msg.Error.Message == "" {
		t.Errorf("%s: error.message must not be empty", vectorID)
	}

	errors := knownErrors()
	if !errors[msg.Error.Code] {
		t.Errorf("%s: unknown error code %d", vectorID, msg.Error.Code)
	}
}

func TestConformanceSessionCreate(t *testing.T) {
	vectors := loadVectors(t, "session-create.json")
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			assertValidRequest(t, v.Input, v.ID)
			if len(v.ExpectedResponse) > 0 {
				assertValidResponse(t, v.ExpectedResponse, v.ID)
			}
		})
	}
}

func TestConformanceSessionLifecycle(t *testing.T) {
	vectors := loadVectors(t, "session-lifecycle.json")
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			assertValidRequest(t, v.Input, v.ID)
			if len(v.ExpectedResponse) > 0 {
				assertValidResponse(t, v.ExpectedResponse, v.ID)
			}
		})
	}
}

func TestConformanceMessageDeliver(t *testing.T) {
	vectors := loadVectors(t, "message-deliver.json")
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			assertValidRequest(t, v.Input, v.ID)
			if len(v.ExpectedResponse) > 0 {
				assertValidResponse(t, v.ExpectedResponse, v.ID)
			}
		})
	}
}

func TestConformanceFlowLifecycle(t *testing.T) {
	vectors := loadVectors(t, "flow-lifecycle.json")
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			// Flow lifecycle may have multi-step sequences in input
			var steps []struct {
				Step    string          `json:"step"`
				Message json.RawMessage `json:"message"`
			}
			if err := json.Unmarshal(v.Input, &steps); err == nil && len(steps) > 0 {
				// Multi-step sequence
				for i, step := range steps {
					sid := fmt.Sprintf("%s/step-%d-%s", v.ID, i, step.Step)
					assertValidRequest(t, step.Message, sid)
				}
			} else {
				// Single input
				assertValidRequest(t, v.Input, v.ID)
			}
			if len(v.ExpectedResponse) > 0 {
				assertValidResponse(t, v.ExpectedResponse, v.ID)
			}
		})
	}
}

func TestConformanceResolve(t *testing.T) {
	vectors := loadVectors(t, "resolve.json")
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			assertValidRequest(t, v.Input, v.ID)
			if len(v.ExpectedResponse) > 0 {
				assertValidResponse(t, v.ExpectedResponse, v.ID)
			}
			if len(v.ExpectedError) > 0 {
				assertValidError(t, v.ExpectedError, v.ID)
			}
		})
	}
}

func TestConformanceErrors(t *testing.T) {
	vectors := loadVectors(t, "errors.json")
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			// Some error vectors use deliberately invalid methods;
			// still validate structure
			var msg genericRPC
			if err := json.Unmarshal(v.Input, &msg); err != nil {
				t.Fatalf("Failed to parse input: %v", err)
			}
			if msg.JSONRPC != "2.0" {
				t.Errorf("jsonrpc = %q, want 2.0", msg.JSONRPC)
			}
			if len(v.ExpectedError) > 0 {
				assertValidError(t, v.ExpectedError, v.ID)
			}
		})
	}
}

func TestConformanceMethodCoverage(t *testing.T) {
	methods := knownMethods()
	vectorMethods := make(map[string]bool)

	files := []string{
		"session-create.json",
		"session-lifecycle.json",
		"message-deliver.json",
		"resolve.json",
	}
	for _, f := range files {
		vectors := loadVectors(t, f)
		for _, v := range vectors {
			var msg genericRPC
			if err := json.Unmarshal(v.Input, &msg); err == nil && msg.Method != "" {
				vectorMethods[msg.Method] = true
			}
		}
	}

	// Verify all vector methods are known
	for m := range vectorMethods {
		if !methods[m] {
			t.Errorf("Vector method %q not in known method constants", m)
		}
	}
}
