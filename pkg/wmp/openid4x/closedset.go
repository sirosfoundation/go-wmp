package openid4x

import (
	"bytes"
	"encoding/json"
	"errors"
)

func isNotNull(raw json.RawMessage) bool { return !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// closedObject decodes raw as a JSON object and refuses duplicate member
// names, which a map decode would silently collapse.
func closedObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if d, ok := tok.(json.Delim); err != nil || !ok || d != '{' {
		return nil, errors.New("not an object")
	}
	m := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		key, ok := kt.(string)
		if err != nil || !ok {
			return nil, errors.New("not an object")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errors.New("not an object")
		}
		if _, dup := m[key]; dup {
			return nil, errors.New("duplicate member")
		}
		m[key] = v
	}
	if _, err := dec.Token(); err != nil || dec.More() {
		return nil, errors.New("not an object")
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("trailing data")
	}
	return m, nil
}
