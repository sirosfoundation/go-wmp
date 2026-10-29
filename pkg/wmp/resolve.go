package wmp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// ResolveReasonMetadataFetchError is the data.reason of the error a vctm
// lookup answers with when it cannot produce a document (WMP Core 5.8.1).
const ResolveReasonMetadataFetchError = "metadata_fetch_error"

// vctmMembers are the members of a type metadata document that a vctm
// resolution carries (WMP Core 5.8.1), in the order they are written.
var vctmMembers = []string{"name", "description", "display", "claims", "schema"}

// ErrVCTMNotObject is returned by ProjectVCTM for a document that is not a JSON
// object, or whose vct is not a string.
var ErrVCTMNotObject = errors.New("wmp: type metadata is not a JSON object")

// ProjectVCTM reduces a type metadata document to the members a vctm
// resolution carries: vct (set to uri when the document has none), and name,
// description, display, claims and schema when present, each verbatim. Any other
// member of the document is dropped. This is the shape the legacy WebSocket
// VCTM flow delivers.
func ProjectVCTM(doc []byte, uri string) (json.RawMessage, error) {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(doc, &all); err != nil || all == nil {
		return nil, ErrVCTMNotObject
	}
	vct := uri
	if raw, ok := all["vct"]; ok && !isJSONNull(raw) {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, ErrVCTMNotObject
		}
		if s != "" {
			vct = s
		}
	}
	if vct == "" {
		return nil, ErrVCTMNotObject
	}
	var out bytes.Buffer
	out.WriteString(`{"vct":`)
	v, _ := json.Marshal(vct)
	out.Write(v)
	for _, name := range vctmMembers {
		raw, ok := all[name]
		if !ok || isJSONNull(raw) {
			continue
		}
		k, _ := json.Marshal(name)
		out.WriteByte(',')
		out.Write(k)
		out.WriteByte(':')
		out.Write(raw)
	}
	out.WriteByte('}')
	return json.RawMessage(out.Bytes()), nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// NewVCTMResolveResult builds the wmp.resolve result of a successful vctm
// lookup from the type metadata document that was found. The document is
// projected with ProjectVCTM; a document that is not an object is an error and
// the caller answers NewMetadataFetchError.
func NewVCTMResolveResult(sessionID, uri string, doc []byte) (*ResolveResult, error) {
	metadata, err := ProjectVCTM(doc, uri)
	if err != nil {
		return nil, fmt.Errorf("vctm %q: %w", uri, err)
	}
	return &ResolveResult{
		WMP:      Metadata{Version: Version, SessionID: sessionID},
		Type:     ResolveTypeVCTM,
		URI:      uri,
		Metadata: metadata,
	}, nil
}

// NewUnknownResolveResult is the result for a resolver that knows the
// identifier is unknown: metadata null. A lookup that cannot tell unknown from
// unreachable (the WebSocket VCTM lookup is one) answers NewMetadataFetchError.
func NewUnknownResolveResult(sessionID, resolveType, uri string) *ResolveResult {
	return &ResolveResult{
		WMP:      Metadata{Version: Version, SessionID: sessionID},
		Type:     resolveType,
		URI:      uri,
		Metadata: json.RawMessage("null"),
	}
}

// NewMetadataFetchError is the error of a vctm lookup that found no document,
// could not reach one, or found one that is not a JSON object: -32603 with
// data {"reason": "metadata_fetch_error"} (WMP Core 5.8.1). It carries nothing
// of the underlying failure.
func NewMetadataFetchError() *RPCError {
	return NewRPCError(ErrInternalError, map[string]string{"reason": ResolveReasonMetadataFetchError})
}

// ValidateVCTMResolveParams reports whether params are a well-formed vctm
// resolve request: an empty uri is invalid params (-32602).
func ValidateVCTMResolveParams(params *ResolveParams) *RPCError {
	if params == nil || params.Type != ResolveTypeVCTM || params.URI == "" {
		return NewRPCError(ErrInvalidParams, nil)
	}
	return nil
}
