// Package qerds is the QERDS sender profile: a registered electronic
// delivery as one call.
//
//	session create (mTLS, or the per-request proof of WMP Core section 4.4.8)
//	-> resolve each recipient and a fresh MLS KeyPackage for it
//	-> an MLS group whose leaf carries the sender's certificate chain
//	-> wmp.mls.group.create (GroupInfo and the Welcome)
//	-> wmp.message.deliver: the ciphertext as the only content field, the
//	   section 5.4 signature and the section 5.6 x509_chain identity assertion
//	-> the evidence repository, polled until the delivery is confirmed
//
// One certificate chain serves every role: the per-request proof, the content
// signature, the MLS leaf credential and the identity assertion (and, in the
// HTTP client the caller supplies, the TLS client certificate).
//
// The MLS cryptography comes from a GroupProvider the caller supplies.
package qerds

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/jcs"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/mls"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/proof"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/signature"
)

// Step is the part of the flow an Error belongs to.
type Step string

// The steps of a send.
const (
	StepConfig   Step = "config"
	StepSession  Step = "session"
	StepResolve  Step = "resolve"
	StepGroup    Step = "group"
	StepDeliver  Step = "deliver"
	StepEvidence Step = "evidence"
)

// Error is a send that did not complete. Err is the *wmp.RPCError of a
// refused request, or what else went wrong.
type Error struct {
	Step Step
	Err  error
}

func (e *Error) Error() string { return fmt.Sprintf("qerds %s: %v", e.Step, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

// Credential is the sender's credential: one certificate chain and the signer
// of its leaf key.
type Credential struct {
	// Chain is the certificate chain, leaf first.
	Chain []*x509.Certificate
	// Signer signs with the leaf's private key (see proof.NewSigner).
	Signer proof.Signer
	// KeyID is a "kid" for the content signature header, next to its "x5c".
	KeyID string
}

// GroupRequest is what a GroupProvider builds a group from.
type GroupRequest struct {
	CipherSuite int
	// Certificates are the sender's DER certificates, leaf first: the X.509
	// credential of the group creator's leaf.
	Certificates [][]byte
	// KeyPackages holds one KeyPackage per recipient.
	KeyPackages map[string]mls.KeyPackage
}

// Group is an MLS group with the recipients added, ready to send in.
type Group interface {
	// ID is the base64url group id.
	ID() string
	// GroupInfo is the base64url MLSMessage carrying the GroupInfo of the
	// epoch the recipients join.
	GroupInfo() string
	// Welcomes is the base64url MLSMessage carrying the Welcome, per recipient.
	Welcomes() map[string]string
	// Encrypt returns an application message as a base64url MLSMessage and
	// the epoch it belongs to.
	Encrypt(plaintext []byte) (ciphertext string, epoch int, err error)
}

// GroupProvider is the MLS engine of the profile.
type GroupProvider interface {
	// CreateGroup creates a group whose own leaf carries the request's
	// certificates as an X.509 credential and adds one member per KeyPackage.
	CreateGroup(ctx context.Context, req GroupRequest) (Group, error)
}

// Message is what is sent.
type Message struct {
	// Body is the message body, a JSON value. Required.
	Body json.RawMessage
	// ContentType defaults to application/json.
	ContentType string
	// ID is the JSON-RPC id of the deliver, which evidence refers to.
	// Default: a fresh unique id.
	ID string
}

// Evidence configures the evidence poll.
type Evidence struct {
	// Skip returns after the deliver without reading the repository.
	Skip bool
	// Until are the event types that end the poll. Default:
	// delivery_confirmed and the terminal failures.
	Until []string
	// Timeout is how long to poll. Default: 90 seconds.
	Timeout time.Duration
	// Interval is the pause between polls. Default: 5 seconds.
	Interval time.Duration
	// Repository is the repository URL. Default: the negotiated
	// evidence.repository, else the endpoint.
	Repository string
}

// Config describes one send.
type Config struct {
	// Endpoint is the WMP HTTPS endpoint of the ERDS: the URL JSON-RPC
	// requests are POSTed to.
	Endpoint string
	// Sender is the sender's participant identifier.
	Sender string
	// Recipients are the recipients' participant identifiers.
	Recipients []string
	Credential Credential
	// Auth is how requests are authenticated. wmp.AuthTypeMTLS: HTTPClient
	// presents the client certificate. wmp.AuthTypeDPoP: each request carries
	// a per-request proof made with the credential. Default: mtls.
	Auth string
	// Responder is the ERDS' participant identifier. Default:
	// x509:san:dns:<host of Endpoint>.
	Responder string
	Message   Message
	// IdentityAssertions of the deliver. Default: one x509_chain assertion
	// with the credential's chain.
	IdentityAssertions []wmp.IdentityAssertion
	// PlaintextHash commits to the plaintext with plaintext_hash (WMP Core
	// section 5.2.1).
	PlaintextHash bool
	// Capabilities offered at session creation. Default: messaging, offline,
	// resolve and evidence.
	Capabilities wmp.Capabilities
	// Security defaults to {mode: "mls", cipher_suites: [1, 2]}.
	Security *wmp.SecurityMode
	// TTL is the session lifetime in seconds. Default: 3600.
	TTL      int
	Evidence Evidence
	// MLS is the MLS engine. Required.
	MLS GroupProvider
	// HTTPClient is the HTTPS client. For mtls it presents the client
	// certificate. Default: http.DefaultClient.
	HTTPClient *http.Client
}

// EvidenceRecord is an evidence record of the repository (WMP Evidence
// section 6.2).
type EvidenceRecord struct {
	EvidenceID        string          `json:"evidence_id"`
	EventType         string          `json:"event_type"`
	EventTime         string          `json:"event_time,omitempty"`
	OriginalMessageID string          `json:"original_message_id,omitempty"`
	OriginalHash      json.RawMessage `json:"original_content_hash,omitempty"`
	SignedEvidence    string          `json:"signed_evidence,omitempty"`
	TimestampToken    string          `json:"timestamp_token,omitempty"`
	// Raw is the record as the repository returned it.
	Raw json.RawMessage `json:"-"`
}

// Sent is what was sent. Keep Content and Signature with Plaintext for as
// long as the evidence: together they show what the evidence attests to.
type Sent struct {
	ID string
	// Content is the outer content object: {"ciphertext": ...}, plus
	// "plaintext_hash" when committed.
	Content json.RawMessage
	// Signature is the wmp.signature value over Content.
	Signature string
	// Plaintext is the plaintext content object that was encrypted.
	Plaintext json.RawMessage
}

// Result is the outcome of a send.
type Result struct {
	SessionID    string
	Security     wmp.SecurityMode
	Capabilities wmp.Capabilities
	GroupID      string
	CipherSuite  int
	Epoch        int
	Message      Sent
	// Evidence holds the evidence records of this message, as last read.
	Evidence []EvidenceRecord
	// Confirmed reports that an event type of Evidence.Until was reached.
	Confirmed bool
}

var (
	defaultEventTypes = []string{
		"submission_accepted", "relay_accepted", "relay_forwarded", "delivery_attempted",
		"delivery_confirmed", "delivery_failed", "retrieval_confirmed", "acceptance_confirmed",
	}
	defaultUntil = []string{"delivery_confirmed", "delivery_failed", "submission_rejected"}
)

const (
	jsonType         = "application/json"
	maxResponse      = 4 << 20
	maxEvidencePages = 100
)

func fail(step Step, format string, a ...any) error {
	return &Error{Step: step, Err: fmt.Errorf(format, a...)}
}

func uniqueID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

func isNull(raw json.RawMessage) bool {
	s := string(bytes.TrimSpace(raw))
	return s == "" || s == "null"
}

func checkRecipients(recipients []string) error {
	if len(recipients) == 0 {
		return fail(StepConfig, "at least one recipient is required")
	}
	seen := map[string]bool{}
	for _, r := range recipients {
		if r == "" {
			return fail(StepConfig, "a recipient is empty")
		}
		if seen[r] {
			return fail(StepConfig, "recipient %s is named twice", r)
		}
		seen[r] = true
	}
	return nil
}

func (c *Config) check() error {
	u, err := url.Parse(c.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fail(StepConfig, "Endpoint is not an absolute http(s) URL")
	}
	if c.Sender == "" {
		return fail(StepConfig, "Sender is required")
	}
	if err := checkRecipients(c.Recipients); err != nil {
		return err
	}
	if len(c.Credential.Chain) == 0 {
		return fail(StepConfig, "Credential.Chain is empty")
	}
	if c.Credential.Signer == nil {
		return fail(StepConfig, "Credential.Signer is required")
	}
	if c.Auth != "" && c.Auth != wmp.AuthTypeMTLS && c.Auth != wmp.AuthTypeDPoP {
		return fail(StepConfig, "Auth %q is not mtls or dpop", c.Auth)
	}
	if isNull(c.Message.Body) || !json.Valid(c.Message.Body) {
		return fail(StepConfig, "Message.Body is not a JSON value")
	}
	if c.MLS == nil {
		return fail(StepConfig, "MLS is required")
	}
	return nil
}

// client is the HTTPS client of one send.
type client struct {
	cfg       *Config
	http      *http.Client
	proofs    *proof.Creator
	x5c       []string
	sessionID string
}

func newClient(cfg *Config) *client {
	c := &client{cfg: cfg, http: cfg.HTTPClient}
	if c.http == nil {
		c.http = http.DefaultClient
	}
	for _, cert := range cfg.Credential.Chain {
		c.x5c = append(c.x5c, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	if cfg.Auth == wmp.AuthTypeDPoP {
		c.proofs = &proof.Creator{Signer: cfg.Credential.Signer, Chain: cfg.Credential.Chain}
	}
	return c
}

// meta is the "wmp" metadata of a request in the session.
func (c *client) meta() wmp.Metadata {
	now := time.Now().UTC().Truncate(time.Second)
	return wmp.Metadata{Version: wmp.Version, SessionID: c.sessionID, Sender: c.cfg.Sender, Timestamp: &now}
}

func (c *client) do(ctx context.Context, method, target string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", jsonType)
	if body != nil {
		req.Header.Set("Content-Type", jsonType)
	}
	if c.sessionID != "" {
		req.Header.Set("Wmp-Session-Id", c.sessionID)
	}
	if c.proofs != nil {
		// A fresh proof per request; the create's proof names no session.
		if err := c.proofs.Authorize(req, c.sessionID); err != nil {
			return nil, 0, err
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, 0, err
	}
	if len(data) > maxResponse {
		return nil, 0, errors.New("response too large")
	}
	return data, resp.StatusCode, nil
}

// call makes one JSON-RPC request; a JSON-RPC error is returned as a
// *wmp.RPCError.
func (c *client) call(ctx context.Context, method, id string, params any) (json.RawMessage, error) {
	if id == "" {
		id = uniqueID("req")
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	data, status, err := c.do(ctx, http.MethodPost, c.cfg.Endpoint, body)
	if err != nil {
		return nil, err
	}
	var answer struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *wmp.RPCError   `json:"error"`
	}
	if json.Unmarshal(data, &answer) != nil {
		return nil, fmt.Errorf("HTTP %d without a JSON-RPC response", status)
	}
	if answer.Error != nil {
		return nil, answer.Error
	}
	if status < 200 || status > 299 {
		return nil, fmt.Errorf("HTTP %d", status)
	}
	var got string
	if json.Unmarshal(answer.ID, &got) != nil || got != id || isNull(answer.Result) {
		return nil, fmt.Errorf("not the response to request %s", id)
	}
	return answer.Result, nil
}

func defaultCapabilities() wmp.Capabilities {
	events, _ := json.Marshal(map[string]any{"event_types": defaultEventTypes})
	return wmp.Capabilities{
		"messaging": json.RawMessage(`{"max_size":65536}`),
		"offline":   json.RawMessage(`{"max_queued":1000,"ttl":2592000,"status_notifications":true}`),
		"resolve":   json.RawMessage(`{"supported_types":["mls_key_packages","participant"]}`),
		"evidence":  events,
	}
}

func (c *client) createSession(ctx context.Context, res *Result) error {
	cfg := c.cfg
	responder := cfg.Responder
	if responder == "" {
		u, _ := url.Parse(cfg.Endpoint)
		responder = "x509:san:dns:" + u.Hostname()
	}
	auth := cfg.Auth
	if auth == "" {
		auth = wmp.AuthTypeMTLS
	}
	params := wmp.SessionCreateParams{
		WMP:                 c.meta(),
		Participants:        []string{responder},
		Auth:                &wmp.AuthObject{Type: auth},
		CapabilitiesOffered: cfg.Capabilities,
		Security:            wmp.SecurityMode{Mode: "mls", CipherSuites: []int{mls.CipherSuiteX25519AES128GCM, mls.CipherSuiteP256AES128GCM}},
		TTL:                 cfg.TTL,
	}
	if params.CapabilitiesOffered == nil {
		params.CapabilitiesOffered = defaultCapabilities()
	}
	if cfg.Security != nil {
		params.Security = *cfg.Security
	}
	if params.TTL == 0 {
		params.TTL = 3600
	}
	raw, err := c.call(ctx, wmp.MethodSessionCreate, "", params)
	if err != nil {
		return err
	}
	var result wmp.SessionCreateResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("the response: %w", err)
	}
	if result.WMP.SessionID == "" {
		return errors.New("the response names no session")
	}
	// The group and the encrypted deliver need a session that negotiated MLS.
	if !strings.HasPrefix(result.Security.Mode, "mls") {
		return fmt.Errorf("the session's security mode is %q, not mls", result.Security.Mode)
	}
	c.sessionID = result.WMP.SessionID
	res.SessionID, res.Security, res.Capabilities = result.WMP.SessionID, result.Security, result.Capabilities
	return nil
}

// resolve returns the document a wmp.resolve answered: its "metadata" member
// when that is an object, otherwise the result itself.
func (c *client) resolve(ctx context.Context, typ, uri string, into any) error {
	raw, err := c.call(ctx, wmp.MethodResolve, "", wmp.ResolveParams{WMP: c.meta(), Type: typ, URI: uri})
	if err != nil {
		return err
	}
	var outer struct {
		Metadata json.RawMessage `json:"metadata"`
	}
	if json.Unmarshal(raw, &outer) == nil && bytes.HasPrefix(bytes.TrimSpace(outer.Metadata), []byte("{")) {
		raw = outer.Metadata
	}
	return json.Unmarshal(raw, into)
}

func (c *client) resolveRecipient(ctx context.Context, recipient string) ([]mls.KeyPackage, error) {
	// Pointers tell an absent or null member from false.
	var participant struct {
		Resolved     *bool `json:"resolved"`
		QERDSCapable *bool `json:"qerds_capable"`
	}
	if err := c.resolve(ctx, "participant", recipient, &participant); err != nil {
		return nil, err
	}
	if participant.Resolved == nil || !*participant.Resolved {
		return nil, errors.New("does not resolve")
	}
	if participant.QERDSCapable == nil || !*participant.QERDSCapable {
		return nil, errors.New("is not QERDS-capable")
	}
	// KeyPackages are single-use (RFC 9420 section 10): resolved fresh for
	// this group.
	var doc struct {
		KeyPackages []struct {
			ID          string `json:"id"`
			CipherSuite *int   `json:"cipher_suite"`
			KeyPackage  string `json:"key_package"`
			Expires     string `json:"expires"`
		} `json:"key_packages"`
	}
	if err := c.resolve(ctx, "mls_key_packages", recipient, &doc); err != nil {
		return nil, err
	}
	if len(doc.KeyPackages) == 0 {
		return nil, errors.New("has no KeyPackage")
	}
	out := make([]mls.KeyPackage, len(doc.KeyPackages))
	for i, kp := range doc.KeyPackages {
		if kp.CipherSuite == nil || kp.KeyPackage == "" {
			return nil, errors.New("has a malformed KeyPackage")
		}
		out[i] = mls.KeyPackage{ID: kp.ID, CipherSuite: *kp.CipherSuite, KeyPackage: kp.KeyPackage, Expires: kp.Expires}
	}
	return out, nil
}

// acceptedSuites are the cipher suites the session negotiated, when it names any.
func acceptedSuites(s wmp.SecurityMode) []int {
	// The suite the responder selected binds; the list is what it would accept.
	if s.CipherSuite != nil {
		return []int{*s.CipherSuite}
	}
	if len(s.CipherSuites) > 0 {
		return s.CipherSuites
	}
	return nil
}

func contains(list []int, v int) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

func packageFor(list []mls.KeyPackage, suite int) (mls.KeyPackage, bool) {
	for _, kp := range list {
		if kp.CipherSuite == suite {
			return kp, true
		}
	}
	return mls.KeyPackage{}, false
}

// selectKeyPackages returns the cipher suite every recipient has a KeyPackage
// for, and that KeyPackage per recipient. The first recipient's order of
// preference decides among the common suites.
func selectKeyPackages(recipients []string, published map[string][]mls.KeyPackage, accepted []int) (int, map[string]mls.KeyPackage, error) {
candidates:
	for _, candidate := range published[recipients[0]] {
		suite := candidate.CipherSuite
		if accepted != nil && !contains(accepted, suite) {
			continue
		}
		picked := make(map[string]mls.KeyPackage, len(recipients))
		for _, r := range recipients {
			kp, ok := packageFor(published[r], suite)
			if !ok {
				continue candidates
			}
			picked[r] = kp
		}
		return suite, picked, nil
	}
	return 0, nil, errors.New("the recipients share no cipher suite the session accepts")
}

func (c *client) createGroup(ctx context.Context, published map[string][]mls.KeyPackage, res *Result) (Group, error) {
	suite, keyPackages, err := selectKeyPackages(c.cfg.Recipients, published, acceptedSuites(res.Security))
	if err != nil {
		return nil, err
	}
	certs := make([][]byte, len(c.cfg.Credential.Chain))
	for i, cert := range c.cfg.Credential.Chain {
		certs[i] = cert.Raw
	}
	group, err := c.cfg.MLS.CreateGroup(ctx, GroupRequest{CipherSuite: suite, Certificates: certs, KeyPackages: keyPackages})
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, errors.New("the MLS engine returned no group")
	}
	welcomes := group.Welcomes()
	for _, r := range c.cfg.Recipients {
		if welcomes[r] == "" {
			return nil, fmt.Errorf("the MLS engine made no Welcome for %s", r)
		}
	}
	_, err = c.call(ctx, mls.MethodGroupCreate, "", mls.GroupCreateParams{
		WMP: c.meta(), GroupID: group.ID(), CipherSuite: suite, GroupInfo: group.GroupInfo(), Welcomes: welcomes,
	})
	if err != nil {
		return nil, err
	}
	res.GroupID, res.CipherSuite = group.ID(), suite
	return group, nil
}

func (c *client) deliver(ctx context.Context, group Group, res *Result) error {
	cfg := c.cfg
	contentType := cfg.Message.ContentType
	if contentType == "" {
		contentType = jsonType
	}
	// The recipients, content type and body travel inside the ciphertext
	// only: a "to" next to "ciphertext" would be read as a plaintext message.
	plain := map[string]any{"to": cfg.Recipients, "content_type": contentType, "body": cfg.Message.Body}
	if cfg.PlaintextHash {
		var salt [16]byte
		if _, err := rand.Read(salt[:]); err != nil {
			return err
		}
		plain["salt"] = base64.RawURLEncoding.EncodeToString(salt[:])
	}
	plaintext, err := jcs.Marshal(plain)
	if err != nil {
		return fmt.Errorf("the message: %w", err)
	}
	ciphertext, epoch, err := group.Encrypt(plaintext)
	if err != nil {
		return err
	}
	if ciphertext == "" {
		return errors.New("the MLS engine returned no ciphertext")
	}
	content := map[string]any{"ciphertext": ciphertext}
	if cfg.PlaintextHash {
		digest := sha256.Sum256(plaintext)
		content["plaintext_hash"] = map[string]string{"algorithm": "sha-256", "value": base64.RawURLEncoding.EncodeToString(digest[:])}
	}
	contentJSON, err := jcs.Marshal(content)
	if err != nil {
		return err
	}
	sig, err := signature.Sign(contentJSON, cfg.Credential.Signer, signature.Options{Chain: cfg.Credential.Chain, KeyID: cfg.Credential.KeyID})
	if err != nil {
		return err
	}

	meta := c.meta()
	meta.Encrypted, meta.Epoch, meta.Signature = true, &epoch, sig
	meta.IdentityAssertions = cfg.IdentityAssertions
	if meta.IdentityAssertions == nil {
		meta.IdentityAssertions = []wmp.IdentityAssertion{{Type: "x509_chain", X5C: c.x5c}}
	}
	params := map[string]any{"wmp": meta}
	for k, v := range content {
		params[k] = v
	}
	id := cfg.Message.ID
	if id == "" {
		id = uniqueID("msg")
	}
	// Recorded before the request: when its answer is lost the ERDS may still
	// have accepted the message, and the caller needs the id to find out.
	res.Epoch = epoch
	res.Message = Sent{ID: id, Content: contentJSON, Signature: sig, Plaintext: plaintext}
	_, err = c.call(ctx, wmp.MethodMessageDeliver, id, params)
	return err
}

func (c *client) repository(res *Result) string {
	if c.cfg.Evidence.Repository != "" {
		return c.cfg.Evidence.Repository
	}
	var evidence struct {
		Repository string `json:"repository"`
	}
	if raw, ok := res.Capabilities["evidence"]; ok && json.Unmarshal(raw, &evidence) == nil && evidence.Repository != "" {
		return evidence.Repository
	}
	return c.cfg.Endpoint
}

// readEvidence returns every evidence record of the session that belongs to
// the message, across pages.
func (c *client) readEvidence(ctx context.Context, repository, messageID string) ([]EvidenceRecord, error) {
	var records []EvidenceRecord
	token := ""
	for page := 0; page < maxEvidencePages; page++ {
		q := url.Values{"session_id": {c.sessionID}}
		if token != "" {
			q.Set("continuation_token", token)
		}
		data, status, err := c.do(ctx, http.MethodGet, strings.TrimRight(repository, "/")+"/evidence?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		if status < 200 || status > 299 {
			return nil, fmt.Errorf("HTTP %d", status)
		}
		var doc struct {
			Records []json.RawMessage `json:"evidence_records"`
			Token   *string           `json:"continuation_token"`
		}
		if err := json.Unmarshal(data, &doc); err != nil || doc.Records == nil {
			return nil, errors.New("no evidence_records")
		}
		for _, raw := range doc.Records {
			var r EvidenceRecord
			if isNull(raw) || json.Unmarshal(raw, &r) != nil || r.EvidenceID == "" || r.EventType == "" {
				return nil, errors.New("a malformed record")
			}
			// The session's records of other messages are not this message's evidence.
			if r.OriginalMessageID == messageID {
				r.Raw = raw
				records = append(records, r)
			}
		}
		if doc.Token == nil || *doc.Token == "" {
			return records, nil
		}
		token = *doc.Token
	}
	return nil, fmt.Errorf("more than %d pages", maxEvidencePages)
}

func reached(records []EvidenceRecord, until []string) bool {
	for _, r := range records {
		for _, u := range until {
			if r.EventType == u {
				return true
			}
		}
	}
	return false
}

func (c *client) pollEvidence(ctx context.Context, res *Result) error {
	ev := c.cfg.Evidence
	until, interval, timeout := ev.Until, ev.Interval, ev.Timeout
	if until == nil {
		until = defaultUntil
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if timeout == 0 {
		timeout = 90 * time.Second
	}
	deadline := time.Now().Add(timeout)
	repository := c.repository(res)
	// The timeout bounds the reads too: a repository that stalls ends the
	// poll unconfirmed, as an elapsed timeout does.
	caller := ctx
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	for {
		records, err := c.readEvidence(ctx, repository, res.Message.ID)
		if err != nil {
			if caller.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			return err
		}
		res.Evidence = records
		if reached(records, until) {
			res.Confirmed = true
			return nil
		}
		if time.Now().Add(interval).After(deadline) {
			return nil
		}
		select {
		case <-caller.Done():
			return caller.Err()
		case <-time.After(interval):
		}
	}
}

// Send sends one message as a registered electronic delivery. It returns the
// session, the group, what was sent and the evidence read so far. A step that
// fails returns an *Error naming it, together with the Result up to that
// step; a poll that ends without one of Evidence.Until returns Confirmed
// false and no error.
func Send(ctx context.Context, cfg Config) (*Result, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	res := &Result{}
	if step, err := newClient(&cfg).run(ctx, res); err != nil {
		return res, &Error{Step: step, Err: err}
	}
	return res, nil
}

// run performs the steps in order and names the one that failed.
func (c *client) run(ctx context.Context, res *Result) (Step, error) {
	if err := c.createSession(ctx, res); err != nil {
		return StepSession, err
	}
	published, err := c.resolveRecipients(ctx)
	if err != nil {
		return StepResolve, err
	}
	group, err := c.createGroup(ctx, published, res)
	if err != nil {
		return StepGroup, err
	}
	if err := c.deliver(ctx, group, res); err != nil {
		return StepDeliver, err
	}
	if c.cfg.Evidence.Skip {
		return "", nil
	}
	return StepEvidence, c.pollEvidence(ctx, res)
}

func (c *client) resolveRecipients(ctx context.Context) (map[string][]mls.KeyPackage, error) {
	published := make(map[string][]mls.KeyPackage, len(c.cfg.Recipients))
	for _, r := range c.cfg.Recipients {
		kps, err := c.resolveRecipient(ctx, r)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r, err)
		}
		published[r] = kps
	}
	return published, nil
}
