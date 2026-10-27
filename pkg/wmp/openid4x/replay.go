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
// as such a completion (or its result already carries redacted_members): the
// caller must then not retain it. The replay copy of a conforming input
// satisfies ValidateCompletionResult.
func SplitReplaySecrets(data []byte) (replay, live []byte, ok bool) {
	mentioned := false
	for _, k := range replaySecretMembers {
		if bytes.Contains(data, []byte(`"`+k+`"`)) {
			mentioned = true
			break
		}
	}
	if !mentioned {
		return data, nil, true
	}
	var env map[string]json.RawMessage
	if json.Unmarshal(data, &env) != nil || env == nil {
		return nil, nil, false
	}
	var method string
	if json.Unmarshal(env["method"], &method) != nil || method != methodFlowComplete {
		return data, nil, true
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(env["params"], &params) != nil || params == nil {
		return nil, nil, false
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(params["result"], &result) != nil || result == nil {
		return nil, nil, false
	}
	var withheld []string // replaySecretMembers is sorted
	for _, k := range replaySecretMembers {
		if _, has := result[k]; has {
			withheld = append(withheld, k)
			delete(result, k)
		}
	}
	if len(withheld) == 0 {
		return data, nil, true
	}
	if _, has := result[redactedMembersKey]; has {
		return nil, nil, false
	}
	var err error
	if result[redactedMembersKey], err = json.Marshal(withheld); err != nil {
		return nil, nil, false
	}
	if params["result"], err = json.Marshal(result); err != nil {
		return nil, nil, false
	}
	if env["params"], err = json.Marshal(params); err != nil {
		return nil, nil, false
	}
	if replay, err = json.Marshal(env); err != nil {
		return nil, nil, false
	}
	return replay, data, true
}
