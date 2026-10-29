package wmp_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
)

// TestVector is the schema for a single WMP conformance test vector.
type TestVector struct {
	ID               string `json:"id"`
	Description      string `json:"description"`
	ConformanceLevel string `json:"conformance_level"`
	// Setup configures the responder under test (spec vectors README); the
	// RPC service harness honours supported_versions.
	Setup struct {
		SupportedVersions []string `json:"supported_versions"`
	} `json:"setup"`
	Input            json.RawMessage `json:"input"`
	ExpectedResponse json.RawMessage `json:"expected_response,omitempty"`
	ExpectedError    json.RawMessage `json:"expected_error,omitempty"`
	// MustRefuse marks a negative vector: the input is a message a conforming
	// receiver MUST refuse, so the conformance check has to report a violation.
	MustRefuse bool   `json:"must_refuse,omitempty"`
	Notes      string `json:"notes,omitempty"`
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
// Searches multiple locations: sibling checkout (local dev), and
// wmp-spec/vectors/ (GitHub Actions CI).
func vectorsDir() string {
	// WMP_VECTORS_DIR overrides the search (for example to run the suite
	// against a spec branch that is not checked out as a sibling).
	if dir := os.Getenv("WMP_VECTORS_DIR"); dir != "" {
		return dir
	}
	_, file, _, _ := runtime.Caller(0)
	base := filepath.Dir(file)

	// Local dev: sibling ../wmp/vectors/ (3 levels up from pkg/wmp/)
	candidates := []string{
		filepath.Join(base, "..", "..", "..", "wmp", "vectors"),
		// CI: wmp-spec/ inside the repo checkout
		filepath.Join(base, "..", "..", "wmp-spec", "vectors"),
	}

	for _, dir := range candidates {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
	}

	// Return first candidate (will trigger skip in loadVectors)
	return candidates[0]
}

func loadVectors(t *testing.T, filename string) []TestVector {
	t.Helper()
	path := filepath.Join(vectorsDir(), filename)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("Vectors not available (%s); checkout leifj/wmp as sibling", path)
		}
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
		wmp.MethodFlowStart:           true,
		wmp.MethodFlowProgress:        true,
		wmp.MethodFlowAction:          true,
		wmp.MethodFlowComplete:        true,
		wmp.MethodFlowError:           true,
		wmp.MethodFlowCancel:          true,
		wmp.MethodResolve:             true,
		wmp.MethodRelayRegister:       true,
	}
}

// knownErrors returns the set of all WMP + JSON-RPC error codes.
func knownErrors() map[int]bool {
	return map[int]bool{
		wmp.ErrParseError:                 true,
		wmp.ErrInvalidRequest:             true,
		wmp.ErrMethodNotFound:             true,
		wmp.ErrInvalidParams:              true,
		wmp.ErrInternalError:              true,
		wmp.ErrSessionNotFound:            true,
		wmp.ErrSessionExpired:             true,
		wmp.ErrNotAuthorized:              true,
		wmp.ErrEncryptionRequired:         true,
		wmp.ErrMLSError:                   true,
		wmp.ErrCapabilityNotSupported:     true,
		wmp.ErrFlowError:                  true,
		wmp.ErrRateLimited:                true,
		wmp.ErrParticipantNotFound:        true,
		wmp.ErrEvidenceRequired:           true,
		wmp.ErrSignatureInvalid:           true,
		wmp.ErrTimestampInvalid:           true,
		wmp.ErrIdentityAssertionInvalid:   true,
		wmp.ErrVersionNotSupported:        true,
		wmp.ErrQueueFull:                  true,
		wmp.ErrDelegationInvalid:          true,
		wmp.ErrConsignmentModeUnsupported: true,
		wmp.ErrAssuranceLevelUnsupported:  true,
		wmp.ErrPolicyUnsupported:          true,
		wmp.ErrPlaintextHashMismatch:      true,
		wmp.ErrIssuerNotEntitled:          true,
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
			if hasJSONValue(v.ExpectedResponse) {
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
			if hasJSONValue(v.ExpectedResponse) {
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
			if hasJSONValue(v.ExpectedResponse) {
				assertValidResponse(t, v.ExpectedResponse, v.ID)
			}
		})
	}
}

// hasJSONValue reports whether raw holds a JSON value other than null. The
// vector schema uses an explicit null expected_response to assert that no
// response is produced (notifications).
func hasJSONValue(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && !bytes.Equal(t, []byte("null"))
}

// engineBlindSignMembers are the sign sub-flow params members of the
// engine-blind encryption design. They must survive a decode into
// openid4x.SignSubFlowParams and back: a member the typed params drop would be
// silently lost by an orchestrator that copies them.
var engineBlindSignMembers = []string{
	"credential_response_encryption", "jwe", "deferred", "response_encryption", "state",
	"auxiliary_data_to_issuer", "credential_type", "credential_issuer",
}

// assertFlowMessage applies the flow-specific conformance checks to a single
// message of a flow-lifecycle vector. A must_refuse vector has to be reported
// as a violation by the check; every other vector has to pass it.
func assertFlowMessage(t *testing.T, raw json.RawMessage, v TestVector, id string, seen flowRecord) {
	t.Helper()
	var msg genericRPC
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("%s: failed to parse message: %v", id, err)
	}
	var violation error
	checked := false
	switch msg.Method {
	case wmp.MethodFlowComplete:
		var p struct {
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(msg.Params, &p); err != nil || len(p.Result) == 0 {
			break
		}
		var fid struct {
			FlowID string `json:"flow_id"`
		}
		_ = json.Unmarshal(msg.Params, &fid)
		checked = true
		if seen.isMatch(fid.FlowID, v.ID) {
			// A match result is validated as one (Section 3.3.2), selected
			// by the flow type recorded at the start, never by its members.
			violation = openid4x.ValidateMatchResult(p.Result, seen.queryIDs(fid.FlowID, p.Result))
		} else {
			violation = openid4x.ValidateCompletionResult(p.Result)
		}
	case wmp.MethodFlowAction:
		var p struct {
			Action string          `json:"action"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(msg.Params, &p); err != nil || p.Action != openid4x.ActionSelectCredentials {
			break
		}
		checked = true
		_, violation = openid4x.ParseSelectCredentials(p.Params)
	case wmp.MethodFlowStart:
		checked = true
		seen.record(msg.Params)
		violation = checkSignParamsRoundTrip(msg.Params)
	}
	if !checked {
		return
	}
	if v.MustRefuse {
		if violation == nil {
			t.Errorf("%s: must_refuse vector passed the conformance check", id)
		}
		return
	}
	if violation != nil {
		t.Errorf("%s: %v", id, violation)
	}
}

// flowRecord remembers, within one vector, the type and DCQL query ids of the
// flows its wmp.flow.start messages began.
type flowRecord map[string]struct {
	flowType string
	ids      []string
}

func (r flowRecord) record(params json.RawMessage) {
	var p struct {
		FlowType string `json:"flow_type"`
		FlowID   string `json:"flow_id"`
		Params   struct {
			DCQL json.RawMessage `json:"dcql_query"`
		} `json:"params"`
	}
	if json.Unmarshal(params, &p) != nil {
		return
	}
	e := r[p.FlowID]
	e.flowType = p.FlowType
	if len(p.Params.DCQL) > 0 {
		e.ids, _ = openid4x.DCQLQueryIDs(p.Params.DCQL)
	}
	r[p.FlowID] = e
}

// isMatch reports whether the flow is a match flow: recorded as one at its
// start or, for a vector that is a lone completion, named flow-match-*.
func (r flowRecord) isMatch(flowID, vectorID string) bool {
	if e, ok := r[flowID]; ok {
		return e.flowType == openid4x.FlowTypeMatch
	}
	return strings.HasPrefix(vectorID, "flow-match-")
}

// queryIDs is the query the result is checked against: the recorded one, or
// (a lone completion) the ids the result itself names.
func (r flowRecord) queryIDs(flowID string, result json.RawMessage) []string {
	if e, ok := r[flowID]; ok && e.ids != nil {
		return e.ids
	}
	var m struct {
		IDs []string `json:"satisfiable_query_ids"`
	}
	_ = json.Unmarshal(result, &m)
	return m.IDs
}

// checkSignParamsRoundTrip verifies, for a sign flow.start, that every
// engine-blind member of params.params survives openid4x.SignSubFlowParams.
func checkSignParamsRoundTrip(params json.RawMessage) error {
	var p struct {
		FlowType string          `json:"flow_type"`
		Params   json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(params, &p); err != nil || p.FlowType != "sign" {
		return nil
	}
	var in map[string]json.RawMessage
	if err := json.Unmarshal(p.Params, &in); err != nil {
		return fmt.Errorf("sign params are not an object: %w", err)
	}
	var typed openid4x.SignSubFlowParams
	if err := json.Unmarshal(p.Params, &typed); err != nil {
		return fmt.Errorf("sign params do not decode: %w", err)
	}
	enc, err := json.Marshal(typed)
	if err != nil {
		return err
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(enc, &out); err != nil {
		return err
	}
	for _, k := range engineBlindSignMembers {
		if _, ok := in[k]; ok {
			if _, kept := out[k]; !kept {
				return fmt.Errorf("sign params member %q is dropped by SignSubFlowParams", k)
			}
		}
	}
	return nil
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
			seen := flowRecord{}
			if err := json.Unmarshal(v.Input, &steps); err == nil && len(steps) > 0 {
				// Multi-step sequence
				for i, step := range steps {
					sid := fmt.Sprintf("%s/step-%d-%s", v.ID, i, step.Step)
					assertValidRequest(t, step.Message, sid)
					assertFlowMessage(t, step.Message, v, sid, seen)
				}
			} else {
				// Single input
				assertValidRequest(t, v.Input, v.ID)
				assertFlowMessage(t, v.Input, v, v.ID, seen)
			}
			if hasJSONValue(v.ExpectedResponse) {
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
			if hasJSONValue(v.ExpectedResponse) {
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

// TestConformanceIssuerEntitlement runs the issuer entitlement vectors (WMP
// OpenID4x 3.1.6 and 7.8) of flow-lifecycle.json against the validators.
func TestConformanceIssuerEntitlement(t *testing.T) {
	var ran int
	for _, v := range loadVectors(t, "flow-lifecycle.json") {
		if !strings.HasPrefix(v.ID, "flow-vci-issuer-entitlement-") && !strings.HasPrefix(v.ID, "flow-vci-refused-") {
			continue
		}
		ran++
		t.Run(v.ID, func(t *testing.T) {
			var msg genericRPC
			if err := json.Unmarshal(v.Input, &msg); err != nil {
				t.Fatal(err)
			}
			switch msg.Method {
			case wmp.MethodFlowProgress:
				checkEntitlementProgressVector(t, msg.Params)
			case wmp.MethodFlowError:
				checkRefusalVector(t, msg.Params)
			}
		})
	}
	if ran == 0 {
		t.Skip("no issuer entitlement vectors in this checkout of the spec")
	}
}

// sameJSON reports whether built, marshaled, is the same JSON value as vector.
func sameJSON(t *testing.T, built any, vector json.RawMessage) bool {
	t.Helper()
	got, err := json.Marshal(built)
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if json.Unmarshal(got, &a) != nil || json.Unmarshal(vector, &b) != nil {
		t.Fatalf("not JSON: %s / %s", got, vector)
	}
	return reflect.DeepEqual(a, b)
}

func checkEntitlementProgressVector(t *testing.T, params json.RawMessage) {
	t.Helper()
	var ps wmp.FlowProgressParams
	if err := json.Unmarshal(params, &ps); err != nil {
		t.Fatal(err)
	}
	p, ok, err := openid4x.ParseIssuerEntitlementPayload(ps.Payload)
	if err != nil || !ok || ps.Step != openid4x.StepTrustEvaluated {
		t.Fatalf("payload refused: ok=%v err=%v step=%s", ok, err, ps.Step)
	}
	// What this library sends for the same result is the vector's payload.
	built, err := openid4x.NewIssuerEntitlementPayload(p.Issuer, p.IssuerEntitlement)
	if err != nil {
		t.Fatal(err)
	}
	if !sameJSON(t, built, ps.Payload) {
		t.Errorf("built payload differs from the vector %s", ps.Payload)
	}
}

// checkRefusalVector checks the -31020 and -31006 refusals of an oid4vci flow.
func checkRefusalVector(t *testing.T, params json.RawMessage) {
	t.Helper()
	var ps wmp.FlowErrorParams
	if err := json.Unmarshal(params, &ps); err != nil {
		t.Fatal(err)
	}
	if ps.Code == wmp.ErrIssuerNotEntitled {
		d, err := openid4x.ParseIssuerNotEntitledData(ps.Data)
		if err != nil || ps.Message != openid4x.IssuerNotEntitledMessage {
			t.Fatalf("-31020 refused: err=%v message=%q", err, ps.Message)
		}
		built, err := openid4x.NewIssuerNotEntitledData(d.Issuer, d.IssuerEntitlement)
		if err != nil {
			t.Fatal(err)
		}
		if !sameJSON(t, built, ps.Data) {
			t.Errorf("built data differs from the vector %s", ps.Data)
		}
		return
	}
	_, ok, err := openid4x.ParseUntrustedIssuerData(ps.Data)
	if err != nil || !ok || ps.Code != wmp.ErrFlowError || ps.Message != wmp.ErrorMessage(wmp.ErrFlowError) {
		t.Fatalf("error refused: ok=%v err=%v code=%d message=%q", ok, err, ps.Code, ps.Message)
	}
	if !sameJSON(t, openid4x.NewUntrustedIssuerData(), ps.Data) {
		t.Errorf("built data differs from the vector %s", ps.Data)
	}
}
