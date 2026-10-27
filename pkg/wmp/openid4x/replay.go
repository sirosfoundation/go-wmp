package openid4x

import (
	"bytes"
	"encoding/json"
)

const (
	methodFlowComplete = "wmp.flow.complete"
	redactedMembersKey = "redacted_members"
)

// SplitReplaySecrets separates a serialised outbound JSON-RPC message into the
// form safe to retain for replay and the live form (WMP OpenID4x profile
// Section 3.1.4).
//
// For a wmp.flow.complete whose result carries any of ReplaySecretMembers,
// replay is the notification with exactly those members removed and
// "redacted_members": [<names withheld, sorted>] added to the result, and live
// is data unchanged. Every other member, credential_metadata included, is
// preserved. For any other message, or a completion with nothing to withhold,
// replay is data and live is nil.
//
// ok is false when the message mentions a secret member but cannot be parsed
// as such a completion (or its result already carries redacted_members, with or without secret members): the
// caller must then not retain it. The replay copy of a conforming input
// satisfies ValidateCompletionResult.
func SplitReplaySecrets(data []byte) (replay, live []byte, ok bool) {
	if !mayNeedRedaction(data) {
		return data, nil, true
	}
	env, isObj := unmarshalObject(data)
	if !isObj {
		return nil, nil, false
	}
	var method string
	if json.Unmarshal(env["method"], &method) != nil || method != methodFlowComplete {
		return data, nil, true
	}
	params, isObj := unmarshalObject(env["params"])
	if !isObj {
		return nil, nil, false
	}
	result, isObj := unmarshalObject(params["result"])
	if !isObj {
		return nil, nil, false
	}
	if _, has := result[redactedMembersKey]; has {
		return nil, nil, false
	}
	withheld := withholdSecrets(result)
	if len(withheld) == 0 {
		return data, nil, true
	}
	replay, ok = reassemble(env, params, result, withheld)
	if !ok {
		return nil, nil, false
	}
	return replay, data, true
}

// mayNeedRedaction reports whether data could carry a secret member or a
// redacted_members member. A JSON key may be spelled with escapes
// ("\u0072efresh_token"), so any escape counts; redacted_members counts
// because a live completion never carries it.
func mayNeedRedaction(data []byte) bool {
	if bytes.Contains(data, []byte(`\u`)) || bytes.Contains(data, []byte(`"`+redactedMembersKey+`"`)) {
		return true
	}
	for _, k := range replaySecretMembers {
		if bytes.Contains(data, []byte(`"`+k+`"`)) {
			return true
		}
	}
	return false
}

func unmarshalObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, false
	}
	return m, true
}

// withholdSecrets deletes the replay secret members from result and returns
// their names, sorted.
func withholdSecrets(result map[string]json.RawMessage) []string {
	var withheld []string // replaySecretMembers is sorted
	for _, k := range replaySecretMembers {
		if _, has := result[k]; has {
			withheld = append(withheld, k)
			delete(result, k)
		}
	}
	return withheld
}

func reassemble(env, params, result map[string]json.RawMessage, withheld []string) ([]byte, bool) {
	var err error
	if result[redactedMembersKey], err = json.Marshal(withheld); err != nil {
		return nil, false
	}
	if params["result"], err = json.Marshal(result); err != nil {
		return nil, false
	}
	if env["params"], err = json.Marshal(params); err != nil {
		return nil, false
	}
	out, err := json.Marshal(env)
	return out, err == nil
}
