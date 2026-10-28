package openid4x

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// FlowTypeMatch is the flow type of the local credential match flow (WMP
// OpenID4x profile Section 3.3). It is a nested flow of an oid4vp flow.
const FlowTypeMatch = "match"

// Codes of a match result that is not satisfiable (Section 3.3.2).
const (
	MatchCodeNoMatch      = "no_match"
	MatchCodeInsufficient = "insufficient"
	MatchCodeError        = "error"
)

// MatchSubFlowParams are the start params of a match sub-flow. They carry only
// data from the verifier's request, nothing about the wallet.
type MatchSubFlowParams struct {
	ParentFlowID string `json:"parent_flow_id"`
	// DCQLQuery is the verifier's DCQL query as the orchestrator validated it.
	DCQLQuery json.RawMessage `json:"dcql_query"`
	// ClientMetadata and VerifiedRequest are the request context of
	// Sections 7.1 and 7.5, opaque here.
	ClientMetadata  json.RawMessage `json:"client_metadata,omitempty"`
	VerifiedRequest json.RawMessage `json:"verified_request,omitempty"`
}

// MatchResult is the result of a match flow. It holds no credential data: a
// closed set of four members.
type MatchResult struct {
	Satisfiable         bool     `json:"satisfiable"`
	SatisfiableQueryIDs []string `json:"satisfiable_query_ids,omitempty"`
	SelectionHandle     string   `json:"selection_handle,omitempty"`
	Code                string   `json:"code,omitempty"`
}

// ErrMatchResult is wrapped by every error ValidateMatchResult returns. Its
// text never contains a member name or value of the offending result.
var ErrMatchResult = errors.New("openid4x: non-conforming match result")

func matchErr(reason string) error { return fmt.Errorf("%w: %s", ErrMatchResult, reason) }

// ValidateMatchResult checks the result of a match flow against the closed set
// of Section 3.3.2 (schema/methods/match-result.json): exactly the members
// satisfiable (boolean, required), satisfiable_query_ids (unique strings, each
// one of queryIDs), selection_handle (22 or more base64url characters) and
// code (no_match, insufficient or error; required when satisfiable is false,
// absent when true). Unknown members, duplicate members, nulls and wrong
// types are refused. It reads only shapes: errors never echo the result.
func ValidateMatchResult(result json.RawMessage, queryIDs []string) error {
	m, err := closedObject(result)
	if err != nil {
		return matchErr(err.Error())
	}
	for k := range m {
		switch k {
		case "satisfiable", "satisfiable_query_ids", "selection_handle", "code":
		default:
			return matchErr("unknown member")
		}
	}
	sat, ok := m["satisfiable"]
	if !ok {
		return matchErr("satisfiable is missing")
	}
	var satisfiable bool
	if !isNotNull(sat) || json.Unmarshal(sat, &satisfiable) != nil {
		return matchErr("satisfiable is not a boolean")
	}
	if raw, ok := m["satisfiable_query_ids"]; ok {
		if err := checkQueryIDs(raw, queryIDs); err != nil {
			return err
		}
	}
	if raw, ok := m["selection_handle"]; ok {
		var h string
		if !isNotNull(raw) || json.Unmarshal(raw, &h) != nil || !validSelectionHandle(h) {
			return matchErr("selection_handle is not a handle")
		}
	}
	raw, hasCode := m["code"]
	if satisfiable && hasCode {
		return matchErr("code present although satisfiable")
	}
	if !satisfiable && !hasCode {
		return matchErr("code missing although not satisfiable")
	}
	if hasCode {
		var c string
		if !isNotNull(raw) || json.Unmarshal(raw, &c) != nil {
			return matchErr("code is not a string")
		}
		switch c {
		case MatchCodeNoMatch, MatchCodeInsufficient, MatchCodeError:
		default:
			return matchErr("code is not a defined code")
		}
	}
	return nil
}

func checkQueryIDs(raw json.RawMessage, queryIDs []string) error {
	var ids []string
	if !isNotNull(raw) || json.Unmarshal(raw, &ids) != nil || ids == nil {
		return matchErr("satisfiable_query_ids is not an array of strings")
	}
	known := make(map[string]bool, len(queryIDs))
	for _, q := range queryIDs {
		known[q] = true
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !known[id] {
			return matchErr("satisfiable_query_ids names an id that is not in the query")
		}
		if seen[id] {
			return matchErr("satisfiable_query_ids repeats an id")
		}
		seen[id] = true
	}
	return nil
}

// DCQLQueryIDs returns the ids of the credential queries of a DCQL query,
// refusing a query that has none or whose ids are empty or repeated.
func DCQLQueryIDs(dcql json.RawMessage) ([]string, error) {
	var q struct {
		Credentials []struct {
			ID string `json:"id"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(dcql, &q); err != nil {
		return nil, errors.New("openid4x: dcql_query is not an object")
	}
	if len(q.Credentials) == 0 {
		return nil, errors.New("openid4x: dcql_query has no credential queries")
	}
	seen := map[string]bool{}
	ids := make([]string, 0, len(q.Credentials))
	for _, c := range q.Credentials {
		if c.ID == "" || seen[c.ID] {
			return nil, errors.New("openid4x: dcql_query credential ids are empty or repeated")
		}
		seen[c.ID] = true
		ids = append(ids, c.ID)
	}
	return ids, nil
}

// RequestMatch asks the wallet, with a nested match flow, whether it can
// satisfy the verifier's DCQL query, and returns the validated result. It
// never asks the wallet for credential data and does not fall back to doing
// so (Section 3.3.2).
//
// A result that does not conform (ValidateMatchResult) is returned as an error
// wrapping ErrMatchResult: the caller ends the oid4vp flow with -32602 and
// access_denied to the verifier, echoing nothing of the result. A rejected
// sub-flow is a *wmp.SubFlowError whose Rejected is true, handled as a
// rejected sign sub-flow (Section 3.2.6).
//
// When the session in ctx did not negotiate the oid4vp capability no match
// flow is sent: the error is a -31005 *wmp.SubFlowError.
func RequestMatch(ctx context.Context, fc *wmp.FlowContext, p MatchSubFlowParams, timeout time.Duration) (json.RawMessage, error) {
	ids, err := DCQLQueryIDs(p.DCQLQuery)
	if err != nil {
		return nil, err
	}
	if sess := wmp.SessionFromContext(ctx); sess != nil && !sess.HasCapability(CapabilityOID4VP) {
		return nil, &wmp.SubFlowError{
			Code:    wmp.ErrCapabilityNotSupported,
			Message: wmp.ErrorMessage(wmp.ErrCapabilityNotSupported),
			Data:    mustJSON(wmp.UnsupportedData(FlowTypeMatch, nil)),
		}
	}
	result, err := fc.RequestSubFlow(ctx, FlowTypeMatch, p, timeout)
	if err != nil {
		return nil, err
	}
	if err := ValidateMatchResult(result, ids); err != nil {
		return nil, err
	}
	return result, nil
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// RequestSign asks the wallet, with a nested sign flow, to sign, and returns
// the sub-flow's result after ValidateCompletionResult. Failures are
// *wmp.SubFlowError with the wallet's code, message and data intact; a
// rejection (Rejected) is -31006 with data.reason "rejected" (Section 3.2.6).
// A result that does not conform is an error wrapping ErrCompletionResult.
func RequestSign(ctx context.Context, fc *wmp.FlowContext, p SignSubFlowParams, timeout time.Duration) (json.RawMessage, error) {
	result, err := fc.RequestSubFlow(ctx, wmp.FlowTypeSign, p, timeout)
	if err != nil {
		return nil, err
	}
	if err := ValidateCompletionResult(result); err != nil {
		return nil, err
	}
	return result, nil
}
