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
// stringMember marks the two that must be strings: a null there is treated as
// absent, while display, claims and schema are carried verbatim, null included
// (Core 9.5 rule 4).
var vctmMembers = []struct {
	name         string
	stringMember bool
}{
	{"name", true}, {"description", true}, {"display", false}, {"claims", false}, {"schema", false},
}

// ErrVCTMInvalid is returned by ProjectVCTM for a type metadata document that
// cannot be carried: it is not a JSON object, its vct, name or description is
// not a string, or it names no vct and the uri is empty.
var ErrVCTMInvalid = errors.New("wmp: invalid type metadata document")

// ProjectVCTM reduces a type metadata document to the members a vctm
// resolution carries: vct (set to uri when the document has none), and name,
// description, display, claims and schema when present, each verbatim. Any other
// member of the document is dropped. This is the shape the legacy WebSocket
// VCTM flow delivers.
func ProjectVCTM(doc []byte, uri string) (json.RawMessage, error) {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(doc, &all); err != nil || all == nil {
		return nil, ErrVCTMInvalid
	}
	vct := uri
	if raw, ok := all["vct"]; ok && !isJSONNull(raw) {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, ErrVCTMInvalid
		}
		if s != "" {
			vct = s
		}
	}
	if vct == "" {
		return nil, ErrVCTMInvalid
	}
	var out bytes.Buffer
	out.WriteString(`{"vct":`)
	v, _ := json.Marshal(vct)
	out.Write(v)
	for _, m := range vctmMembers {
		raw, ok := all[m.name]
		if !ok {
			continue
		}
		if m.stringMember {
			if isJSONNull(raw) {
				continue
			}
			var str string
			if json.Unmarshal(raw, &str) != nil {
				return nil, ErrVCTMInvalid
			}
		}
		k, _ := json.Marshal(m.name)
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
