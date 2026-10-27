package openid4x

import (
	"bytes"
	"encoding/json"
	"io"
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
	if rawMethod, has := env["method"]; has {
		var method *string
		if json.Unmarshal(rawMethod, &method) != nil || method == nil {
			return nil, nil, false
		}
		if *method != methodFlowComplete {
			return data, nil, true
		}
	} else {
		return data, nil, true // a response or malformed non-notification carries no completion
	}
	replay, changed, ok := redactCompletion(env)
	switch {
	case !ok:
		return nil, nil, false
	case !changed:
		return data, nil, true
	}
	return replay, data, true
}

// redactCompletion redacts the result of a decoded wmp.flow.complete
// envelope. changed is false when there was nothing to withhold.
func redactCompletion(env map[string]json.RawMessage) (replay []byte, changed, ok bool) {
	params, isObj := unmarshalObject(env["params"])
	if !isObj {
		return nil, false, false
	}
	rawResult, has := params["result"]
	if !has {
		return nil, false, true // result is optional
	}
	result, isObj := unmarshalObject(rawResult)
	if !isObj {
		return nil, false, false
	}
	if _, has := result[redactedMembersKey]; has {
		return nil, false, false
	}
	withheld := withholdSecrets(result)
	if len(withheld) == 0 {
		return nil, false, true
	}
	replay, ok = reassemble(env, params, result, withheld)
	return replay, ok, ok
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

// unmarshalObject decodes a JSON object into its members. It reports false
// for anything but exactly one object whose keys are distinct after unescaping:
// a duplicate key would otherwise let a decoder keep one value while another
// reader sees the other.
func unmarshalObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	m := map[string]json.RawMessage{}
	for dec.More() {
		keyTok, err := dec.Token()
		key, isStr := keyTok.(string)
		if err != nil || !isStr {
			return nil, false
		}
		if _, dup := m[key]; dup {
			return nil, false
		}
		var val json.RawMessage
		if dec.Decode(&val) != nil {
			return nil, false
		}
		m[key] = val
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
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
