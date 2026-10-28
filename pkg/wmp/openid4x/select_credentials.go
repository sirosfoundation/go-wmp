package openid4x

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// MaxQueryIDLen is the longest query_id of a selection (Section 3.2.3.1).
const MaxQueryIDLen = 256

// QuerySelection is one element of the selections of a select_credentials
// action: the verifier's own query id and the opaque per-flow handle, and
// nothing else. The orchestrator learns neither the credential nor the claims.
type QuerySelection struct {
	QueryID         string `json:"query_id"`
	SelectionHandle string `json:"selection_handle"`
}

// SelectCredentialsParams are the params of a select_credentials action
// (WMP OpenID4x profile Section 3.2.3.1): a closed set. Build one to send;
// decode a received one only with ParseSelectCredentials, which refuses
// everything the type cannot hold (an unknown member would be dropped by a
// plain json.Unmarshal, which would still have received it).
type SelectCredentialsParams struct {
	Consent    bool             `json:"consent"`
	Selections []QuerySelection `json:"selections,omitempty"`
}

// ErrSelectCredentials is wrapped by every error ParseSelectCredentials and
// Check return. Its text never contains a member name or value of the
// offending params.
//
// The caller refuses as Section 3.2.3.1 says: it answers the wmp.flow.action
// with a JSON-RPC error -32602 without data, ends the oid4vp flow with a
// terminal wmp.flow.error -32602 whose data echoes nothing of the params,
// reports access_denied to the verifier, and neither logs, stores nor
// forwards the offending members.
var ErrSelectCredentials = errors.New("openid4x: non-conforming select_credentials params")

func selErr(reason string) error { return fmt.Errorf("%w: %s", ErrSelectCredentials, reason) }

// ParseSelectCredentials decodes and validates the params of a
// select_credentials action against schema/methods/select-credentials-params.json
// and the rules of Section 3.2.3.1 that need no request:
//
//   - exactly the members consent (boolean, required) and selections; each
//     selection has exactly query_id and selection_handle, both required
//     strings; unknown members, duplicate members, nulls and wrong types are
//     refused;
//   - consent true needs at least one selection; consent false needs none;
//   - a query_id is 1 to 256 characters without whitespace or control,
//     zero-width or byte-order-mark characters;
//   - a selection_handle is 22 or more base64url characters without padding;
//     it is the same in every selection;
//   - no query_id is repeated.
//
// That each query_id is an id of the verifier's request, and that the handle
// is the match result's, is Check.
func ParseSelectCredentials(raw json.RawMessage) (*SelectCredentialsParams, error) {
	m, err := closedObject(raw)
	if err != nil {
		return nil, selErr(err.Error())
	}
	for k := range m {
		if k != "consent" && k != "selections" {
			return nil, selErr("unknown member")
		}
	}
	var p SelectCredentialsParams
	c, ok := m["consent"]
	if !ok || !isNotNull(c) || json.Unmarshal(c, &p.Consent) != nil {
		return nil, selErr("consent is not a boolean")
	}
	if rawSel, ok := m["selections"]; ok {
		if p.Selections, err = parseSelections(rawSel); err != nil {
			return nil, err
		}
	}
	switch {
	case p.Consent && len(p.Selections) == 0:
		return nil, selErr("consent without selections")
	case !p.Consent && len(p.Selections) > 0:
		return nil, selErr("selections although consent is false")
	}
	return &p, nil
}

func parseSelections(raw json.RawMessage) ([]QuerySelection, error) {
	var els []json.RawMessage
	if !isNotNull(raw) || json.Unmarshal(raw, &els) != nil || els == nil {
		return nil, selErr("selections is not an array")
	}
	out := make([]QuerySelection, 0, len(els))
	seen := make(map[string]bool, len(els))
	for _, el := range els {
		sel, err := parseSelection(el)
		if err != nil {
			return nil, err
		}
		if seen[sel.QueryID] {
			return nil, selErr("a query_id is repeated")
		}
		seen[sel.QueryID] = true
		if len(out) > 0 && sel.SelectionHandle != out[0].SelectionHandle {
			return nil, selErr("selection_handle differs between selections")
		}
		out = append(out, sel)
	}
	return out, nil
}

func parseSelection(raw json.RawMessage) (QuerySelection, error) {
	var sel QuerySelection
	m, err := closedObject(raw)
	if err != nil {
		return sel, selErr("a selection is not an object")
	}
	for k := range m {
		if k != "query_id" && k != "selection_handle" {
			return sel, selErr("a selection has an unknown member")
		}
	}
	q, hasQ := m["query_id"]
	h, hasH := m["selection_handle"]
	if !hasQ || !hasH {
		return sel, selErr("a selection lacks query_id or selection_handle")
	}
	if !isNotNull(q) || json.Unmarshal(q, &sel.QueryID) != nil || !validQueryID(sel.QueryID) {
		return sel, selErr("query_id is not a query id")
	}
	if !isNotNull(h) || json.Unmarshal(h, &sel.SelectionHandle) != nil || !validSelectionHandle(sel.SelectionHandle) {
		return sel, selErr("selection_handle is not a handle")
	}
	return sel, nil
}

// validQueryID applies the form check of Section 3.2.3.1: 1 to 256
// characters, none of them ASCII or Unicode whitespace, a C0 or C1 control, a
// zero-width character or the byte-order mark.
func validQueryID(id string) bool {
	n := utf8.RuneCountInString(id)
	if n < 1 || n > MaxQueryIDLen || !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		switch {
		case r <= 0x20, r >= 0x7f && r <= 0xa0, r == 0x1680,
			r >= 0x2000 && r <= 0x200b, r >= 0x2028 && r <= 0x202f,
			r >= 0x205f && r <= 0x2060, r == 0x3000, r == 0xfeff:
			return false
		}
	}
	return true
}

// Check applies what only the orchestrator, which holds the verifier's
// request, can: every query_id is one of requestQueryIDs (the ids of the
// DCQL credential queries, or of the input descriptors of a Presentation
// Exchange request), and, when the match result carried a handle
// (matchHandle non-empty), the selections' handle is that handle.
func (p *SelectCredentialsParams) Check(requestQueryIDs []string, matchHandle string) error {
	known := make(map[string]bool, len(requestQueryIDs))
	for _, id := range requestQueryIDs {
		known[id] = true
	}
	for _, s := range p.Selections {
		if !known[s.QueryID] {
			return selErr("a query_id is not an id in the request")
		}
		if matchHandle != "" && s.SelectionHandle != matchHandle {
			return selErr("selection_handle differs from the match result's")
		}
	}
	return nil
}

// SignInclusion returns what the sign_presentation that follows a consenting
// action carries: credentials_to_include and selection_handle (Section
// 3.2.5). Both are empty for a declined action.
func (p *SelectCredentialsParams) SignInclusion() ([]CredentialQueryRef, string) {
	if !p.Consent || len(p.Selections) == 0 {
		return nil, ""
	}
	refs := make([]CredentialQueryRef, len(p.Selections))
	for i, s := range p.Selections {
		refs[i] = CredentialQueryRef{CredentialQueryID: s.QueryID}
	}
	return refs, p.Selections[0].SelectionHandle
}
