package wmp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	defaultMaxMessageSize = 1 << 20 // 1 MB
	defaultMaxDepth       = 32
)

// DecodeOptions controls safety limits for JSON-RPC decoding.
type DecodeOptions struct {
	// MaxSize is the maximum message size in bytes.
	MaxSize int
	// MaxDepth is the maximum nesting depth for arrays/objects.
	MaxDepth int
}

func (o *DecodeOptions) maxSize() int {
	if o == nil || o.MaxSize <= 0 {
		return defaultMaxMessageSize
	}
	return o.MaxSize
}

func (o *DecodeOptions) maxDepth() int {
	if o == nil || o.MaxDepth <= 0 {
		return defaultMaxDepth
	}
	return o.MaxDepth
}

// Request is a JSON-RPC 2.0 request or notification.
// Notifications have ID == nil.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// IsNotification returns true if this is a notification (no ID).
func (r *Request) IsNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("wmp: rpc error %d: %s", e.Code, e.Message)
}

// NewRPCError creates an RPCError with the standard message for a WMP error code.
func NewRPCError(code int, data interface{}) *RPCError {
	e := &RPCError{
		Code:    code,
		Message: ErrorMessage(code),
	}
	if data != nil {
		e.Data, _ = json.Marshal(data)
	}
	return e
}

// NewRequest creates a JSON-RPC 2.0 request.
func NewRequest(id string, method string, params interface{}) (*Request, error) {
	p, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}
	r := &Request{
		JSONRPC: "2.0",
		Method:  method,
		Params:  p,
	}
	if id != "" {
		r.ID, _ = json.Marshal(id)
	}
	return r, nil
}

// NewNotification creates a JSON-RPC 2.0 notification (no id).
func NewNotification(method string, params interface{}) (*Request, error) {
	return NewRequest("", method, params)
}

// NewResponse creates a successful JSON-RPC 2.0 response.
func NewResponse(id json.RawMessage, result interface{}) (*Response, error) {
	r, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  r,
	}, nil
}

// NewErrorResponse creates a JSON-RPC 2.0 error response.
func NewErrorResponse(id json.RawMessage, rpcErr *RPCError) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   rpcErr,
	}
}

// Message is a union type that can be a Request or Response.
// Used when reading from a transport where the message type is unknown.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// IsRequest returns true if this is a request or notification (has method).
func (m *Message) IsRequest() bool {
	return m.Method != ""
}

// IsResponse returns true if this is a response (has result or error).
func (m *Message) IsResponse() bool {
	return m.Result != nil || m.Error != nil
}

// AsRequest converts a Message to a Request.
func (m *Message) AsRequest() *Request {
	return &Request{
		JSONRPC: m.JSONRPC,
		ID:      m.ID,
		Method:  m.Method,
		Params:  m.Params,
	}
}

// AsResponse converts a Message to a Response.
func (m *Message) AsResponse() *Response {
	return &Response{
		JSONRPC: m.JSONRPC,
		ID:      m.ID,
		Result:  m.Result,
		Error:   m.Error,
	}
}

// DecodeMessage decodes raw JSON into a Message.
func DecodeMessage(data []byte, opts ...*DecodeOptions) (*Message, error) {
	var opt *DecodeOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	if len(data) > opt.maxSize() {
		return nil, fmt.Errorf("message exceeds maximum size of %d bytes", opt.maxSize())
	}

	var msg Message
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&msg); err != nil {
		return nil, fmt.Errorf("decode message: %w", err)
	}
	if msg.JSONRPC != "2.0" {
		return nil, fmt.Errorf("unsupported jsonrpc version: %q", msg.JSONRPC)
	}

	if err := checkMessageDepth(&msg, opt.maxDepth()); err != nil {
		return nil, err
	}
	if err := requireEOF(dec); err != nil {
		return nil, err
	}
	return &msg, nil
}

// DecodeBatch attempts to decode a JSON array as a batch of messages.
// Returns nil if the data is not a JSON array.
func DecodeBatch(data []byte, opts ...*DecodeOptions) ([]*Message, error) {
	var opt *DecodeOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	if len(data) > opt.maxSize() {
		return nil, fmt.Errorf("message exceeds maximum size of %d bytes", opt.maxSize())
	}

	data = trimSpace(data)
	if len(data) == 0 || data[0] != '[' {
		return nil, nil
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var msgs []*Message
	if err := dec.Decode(&msgs); err != nil {
		return nil, fmt.Errorf("decode batch: %w", err)
	}
	for _, msg := range msgs {
		if msg.JSONRPC != "2.0" {
			return nil, fmt.Errorf("unsupported jsonrpc version in batch: %q", msg.JSONRPC)
		}
		if err := checkMessageDepth(msg, opt.maxDepth()); err != nil {
			return nil, err
		}
	}
	if err := requireEOF(dec); err != nil {
		return nil, err
	}
	return msgs, nil
}

// requireEOF returns an error if the decoder has remaining non-whitespace data.
func requireEOF(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode error: %w", err)
	}
	return fmt.Errorf("trailing data after JSON-RPC message: %v", tok)
}

func trimSpace(data []byte) []byte {
	for len(data) > 0 && (data[0] == ' ' || data[0] == '\t' || data[0] == '\n' || data[0] == '\r') {
		data = data[1:]
	}
	return data
}

// checkMessageDepth verifies that nested Params/Result/Error/Data raw messages
// do not exceed the configured depth. It unmarshals the raw JSON into generic
// values and measures nesting.
func checkMessageDepth(msg *Message, maxDepth int) error {
	check := func(raw json.RawMessage) error {
		if len(raw) == 0 {
			return nil
		}
		var v interface{}
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil // let normal decoding report parse errors later
		}
		if depth(v) > maxDepth {
			return fmt.Errorf("message exceeds maximum nesting depth of %d", maxDepth)
		}
		return nil
	}
	if err := check(msg.Params); err != nil {
		return err
	}
	if err := check(msg.Result); err != nil {
		return err
	}
	if msg.Error != nil && msg.Error.Data != nil {
		if err := check(msg.Error.Data); err != nil {
			return err
		}
	}
	return nil
}

func depth(v interface{}) int {
	switch x := v.(type) {
	case map[string]interface{}:
		max := 1
		for _, child := range x {
			if d := depth(child); d+1 > max {
				max = d + 1
			}
		}
		return max
	case []interface{}:
		max := 1
		for _, child := range x {
			if d := depth(child); d+1 > max {
				max = d + 1
			}
		}
		return max
	case json.Number:
		// Treat numbers as scalars, but also handle strings that look like
		// numbers for safety — depth 1.
		if _, err := x.Int64(); err == nil {
			return 1
		}
		if _, err := strconv.ParseFloat(string(x), 64); err == nil {
			return 1
		}
		return 1
	case string:
		if strings.TrimSpace(x) == "" {
			return 1
		}
		return 1
	default:
		return 1
	}
}
