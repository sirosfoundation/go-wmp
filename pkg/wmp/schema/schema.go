// Package schema provides WMP JSON Schema validation.
//
// The JSON Schema files from the WMP specification (JSON Schema 2020-12)
// are embedded at build time and used to validate WMP messages at runtime.
//
// Usage:
//
//	v, err := schema.NewValidator()
//	if err != nil { ... }
//	if err := v.ValidateMethod("wmp.session.create", requestBytes); err != nil {
//	    // validation error
//	}
package schema

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed *.json methods/*.json
var schemaFS embed.FS

// methodSchemaMap maps WMP method names to their schema file paths.
var methodSchemaMap = map[string]string{
	"wmp.session.create":    "methods/session-create-request.json",
	"wmp.session.close":     "methods/session-close.json",
	"wmp.flow.start":        "methods/flow-start.json",
	"wmp.flow.progress":     "methods/flow-progress.json",
	"wmp.flow.action":       "methods/flow-action.json",
	"wmp.flow.complete":     "methods/flow-complete.json",
	"wmp.flow.error":        "methods/flow-error.json",
	"wmp.resolve":           "methods/resolve-request.json",
	"wmp.message.deliver":   "methods/message-deliver.json",
	"wmp.message.ack":       "methods/message-ack.json",
	"wmp.capability.update": "methods/capability-update-request.json",
}

// responseSchemaMap maps WMP method names to their response schema file paths.
var responseSchemaMap = map[string]string{
	"wmp.session.create":    "methods/session-create-response.json",
	"wmp.resolve":           "methods/resolve-response.json",
	"wmp.capability.list":   "methods/capability-list-response.json",
}

// Validator validates WMP messages against embedded JSON Schemas.
type Validator struct {
	compiler *jsonschema.Compiler
	mu       sync.RWMutex
	compiled map[string]*jsonschema.Schema
	strict   bool
}

// ValidatorOption configures a Validator.
type ValidatorOption func(*Validator)

// WithStrict enables strict mode: unknown methods/responses are reported as
// validation errors instead of being silently accepted.
func WithStrict(strict bool) ValidatorOption {
	return func(v *Validator) { v.strict = strict }
}

// NewValidator creates a new schema validator with all embedded schemas loaded.
func NewValidator(opts ...ValidatorOption) (*Validator, error) {
	c := jsonschema.NewCompiler()

	// Load all embedded schema files into the compiler.
	err := fs.WalkDir(schemaFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		data, err := schemaFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading embedded schema %s: %w", path, err)
		}

		// Decode to interface{} for AddResource.
		var doc interface{}
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parsing schema %s: %w", path, err)
		}

		// Register by file path for $ref resolution.
		if err := c.AddResource(path, doc); err != nil {
			return fmt.Errorf("adding schema %s: %w", path, err)
		}

		// Also register by $id if present, so absolute $ref URLs resolve.
		var meta struct {
			ID string `json:"$id"`
		}
		if err := json.Unmarshal(data, &meta); err == nil && meta.ID != "" {
			if err := c.AddResource(meta.ID, doc); err != nil {
				return fmt.Errorf("adding schema by $id %s: %w", meta.ID, err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("loading embedded schemas: %w", err)
	}

	v := &Validator{
		compiler: c,
		compiled: make(map[string]*jsonschema.Schema),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

// ValidateMethod validates a JSON-RPC request message against the schema
// for the given WMP method. Returns nil if valid. In strict mode, unknown
// methods return an error; otherwise they are silently accepted.
func (v *Validator) ValidateMethod(method string, data []byte) error {
	schemaPath, ok := methodSchemaMap[method]
	if !ok {
		if v.strict {
			return fmt.Errorf("no schema defined for method %q", method)
		}
		return nil
	}
	return v.validate(schemaPath, data)
}

// ValidateResponse validates a JSON-RPC response message against the response
// schema for the given WMP method.
func (v *Validator) ValidateResponse(method string, data []byte) error {
	schemaPath, ok := responseSchemaMap[method]
	if !ok {
		if v.strict {
			return fmt.Errorf("no response schema defined for method %q", method)
		}
		return nil
	}
	return v.validate(schemaPath, data)
}

// ValidateMetadata validates a WMP metadata object against the metadata schema.
func (v *Validator) ValidateMetadata(data []byte) error {
	return v.validate("wmp-metadata.json", data)
}

// MethodSchemas returns the list of methods that have request schemas.
func (v *Validator) MethodSchemas() []string {
	methods := make([]string, 0, len(methodSchemaMap))
	for m := range methodSchemaMap {
		methods = append(methods, m)
	}
	return methods
}

// validate compiles and caches a schema, then validates data against it.
func (v *Validator) validate(schemaPath string, data []byte) error {
	schema, err := v.getSchema(schemaPath)
	if err != nil {
		return fmt.Errorf("compiling schema %s: %w", schemaPath, err)
	}

	var value interface{}
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("parsing JSON: %w", err)
	}

	return schema.Validate(value)
}

func (v *Validator) getSchema(path string) (*jsonschema.Schema, error) {
	v.mu.RLock()
	s, ok := v.compiled[path]
	v.mu.RUnlock()
	if ok {
		return s, nil
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Double-check after acquiring write lock.
	if s, ok := v.compiled[path]; ok {
		return s, nil
	}

	s, err := v.compiler.Compile(path)
	if err != nil {
		return nil, err
	}
	v.compiled[path] = s
	return s, nil
}
