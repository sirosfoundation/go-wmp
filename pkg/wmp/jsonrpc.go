package wmp

import (
	"encoding/json"
	"fmt"
)

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
func DecodeMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("decode message: %w", err)
	}
	if msg.JSONRPC != "2.0" {
		return nil, fmt.Errorf("unsupported jsonrpc version: %q", msg.JSONRPC)
	}
	return &msg, nil
}

// DecodeBatch attempts to decode a JSON array as a batch of messages.
// Returns nil if the data is not a JSON array.
func DecodeBatch(data []byte) ([]*Message, error) {
	data = trimSpace(data)
	if len(data) == 0 || data[0] != '[' {
		return nil, nil
	}
	var msgs []*Message
	if err := json.Unmarshal(data, &msgs); err != nil {
		return nil, fmt.Errorf("decode batch: %w", err)
	}
	for _, msg := range msgs {
		if msg.JSONRPC != "2.0" {
			return nil, fmt.Errorf("unsupported jsonrpc version in batch: %q", msg.JSONRPC)
		}
	}
	return msgs, nil
}

func trimSpace(data []byte) []byte {
	for len(data) > 0 && (data[0] == ' ' || data[0] == '\t' || data[0] == '\n' || data[0] == '\r') {
		data = data[1:]
	}
	return data
}
