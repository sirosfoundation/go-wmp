package wmp_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// InteropVector is a cross-implementation behavioral test vector.
type InteropVector struct {
	ID               string          `json:"id"`
	Description      string          `json:"description"`
	ConformanceLevel string          `json:"conformance_level"`
	Input            json.RawMessage `json:"input"`
	ExpectedResponse json.RawMessage `json:"expected_response,omitempty"`
	ExpectedError    json.RawMessage `json:"expected_error,omitempty"`
	HandlerAction    *handlerAction  `json:"handler_action,omitempty"`
	PeerOptions      *peerOptions    `json:"peer_options,omitempty"`
	Notes            string          `json:"notes,omitempty"`
}

type handlerAction struct {
	Method string          `json:"method"`
	Return json.RawMessage `json:"return,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
}

type peerOptions struct {
	Authorize *bool `json:"authorize,omitempty"`
	Validate  *bool `json:"validate,omitempty"`
}

// interopHandler returns deterministic results controlled by the test vector.
type interopHandler struct {
	wmp.BaseHandler
	action *handlerAction
}

func (h *interopHandler) Resolve(_ context.Context, params *wmp.ResolveParams) (*wmp.ResolveResult, error) {
	if h.action == nil || h.action.Method != wmp.MethodResolve {
		return nil, wmp.NewRPCError(wmp.ErrMethodNotFound, nil)
	}
	if len(h.action.Error) > 0 {
		var rpcErr wmp.RPCError
		if err := json.Unmarshal(h.action.Error, &rpcErr); err != nil {
			return nil, err
		}
		return nil, &rpcErr
	}
	if len(h.action.Return) > 0 {
		var result wmp.ResolveResult
		if err := json.Unmarshal(h.action.Return, &result); err != nil {
			return nil, err
		}
		return &result, nil
	}
	return nil, wmp.NewRPCError(wmp.ErrMethodNotFound, nil)
}

// staticValidator rejects all methods when configured to fail.
type staticValidator struct {
	valid bool
}

func (v staticValidator) ValidateMethod(method string, _ []byte) error {
	_ = method
	if !v.valid {
		return errors.New("rejected by test validator")
	}
	return nil
}

// staticAuthorizer rejects all methods when configured to fail.
type staticAuthorizer struct {
	allowed bool
}

func (a staticAuthorizer) Authorize(_ context.Context, method string, _ json.RawMessage) bool {
	_ = method
	return a.allowed
}

func loadInteropVectors(t *testing.T) []InteropVector {
	t.Helper()
	path := filepath.Join(vectorsDir(), "interop.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("Interop vectors not available (%s); checkout leifj/wmp as sibling", path)
		}
		t.Fatalf("Failed to read %s: %v", path, err)
	}
	var vectors []InteropVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse interop.json: %v", err)
	}
	return vectors
}

// normalizeJSON re-encodes JSON so structural equality ignores key ordering.
func normalizeJSON(raw json.RawMessage) (map[string]interface{}, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var v map[string]interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func TestInteropVectors(t *testing.T) {
	vectors := loadInteropVectors(t)
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			ctx := context.Background()

			handler := &interopHandler{action: v.HandlerAction}
			opts := []wmp.PeerOption{wmp.WithMaxMessageSize(1 << 20)}
			if v.PeerOptions != nil {
				if v.PeerOptions.Authorize != nil && !*v.PeerOptions.Authorize {
					opts = append(opts, wmp.WithAuthorizer(staticAuthorizer{allowed: false}))
				}
				if v.PeerOptions.Validate != nil && !*v.PeerOptions.Validate {
					opts = append(opts, wmp.WithValidator(staticValidator{valid: false}))
				}
			}

			// Transport is not used by HandleRequestSync.
			peer := wmp.NewPeer(nil, handler, opts...)

			respBytes, err := peer.HandleRequestSync(ctx, v.Input)
			if err != nil {
				t.Fatalf("HandleRequestSync returned unexpected error: %v", err)
			}

			// Notification-style vectors expect no response.
			if v.ExpectedResponse != nil && len(v.ExpectedResponse) > 0 && string(v.ExpectedResponse) == "null" {
				if len(respBytes) > 0 {
					t.Fatalf("expected no response for notification, got %s", string(respBytes))
				}
				return
			}

			if len(v.ExpectedError) > 0 {
				if len(respBytes) == 0 {
					t.Fatalf("expected error response, got none")
				}
				var actual genericRPC
				if err := json.Unmarshal(respBytes, &actual); err != nil {
					t.Fatalf("failed to parse actual response: %v", err)
				}
				var expected genericRPC
				if err := json.Unmarshal(v.ExpectedError, &expected); err != nil {
					t.Fatalf("failed to parse expected error: %v", err)
				}
				if actual.Error == nil {
					t.Fatalf("expected error, got success response: %s", string(respBytes))
				}
				if actual.Error.Code != expected.Error.Code {
					t.Fatalf("error code mismatch: got %d, want %d", actual.Error.Code, expected.Error.Code)
				}
				// Error message may vary; assert it is non-empty.
				if actual.Error.Message == "" {
					t.Fatalf("error message must not be empty")
				}
				return
			}

			if len(v.ExpectedResponse) > 0 {
				if len(respBytes) == 0 {
					t.Fatalf("expected success response, got none")
				}
				actualNorm, err := normalizeJSON(respBytes)
				if err != nil {
					t.Fatalf("failed to normalize actual response: %v", err)
				}
				expectedNorm, err := normalizeJSON(v.ExpectedResponse)
				if err != nil {
					t.Fatalf("failed to normalize expected response: %v", err)
				}
				if !reflect.DeepEqual(actualNorm, expectedNorm) {
					t.Fatalf("response mismatch\nactual:   %s\nexpected: %s", string(respBytes), string(v.ExpectedResponse))
				}
				return
			}

			// No expectation means no response should be produced.
			if len(respBytes) > 0 {
				t.Fatalf("expected no response, got %s", string(respBytes))
			}
		})
	}
}
