package qerds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/jcs"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/mls"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/proof"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/signature"
)

const (
	sender = "ebcore:iso6523:0007:5595421925"
	bob    = "ebcore:iso6523:0106:99900817"
	carol  = "ebcore:iso6523:0106:11111111"
	sid    = "ses-qerds-1"
)

var b64u = base64.RawURLEncoding

// fakeGroup stands in for an MLS engine: its "ciphertext" is the plaintext,
// encoded, so a test can read what was encrypted.
type fakeGroup struct {
	req   GroupRequest
	epoch int
}

func (g *fakeGroup) ID() string        { return "Z3JvdXAtMQ" }
func (g *fakeGroup) GroupInfo() string { return "Z3JvdXAtaW5mbw" }
func (g *fakeGroup) Welcomes() map[string]string {
	out := map[string]string{}
	for r, kp := range g.req.KeyPackages {
		out[r] = b64u.EncodeToString([]byte("welcome:" + kp.KeyPackage))
	}
	return out
}
func (g *fakeGroup) Encrypt(plaintext []byte) (string, int, error) {
	return b64u.EncodeToString(plaintext), g.epoch, nil
}

type fakeMLS struct {
	requests []GroupRequest
	err      error
}

func (m *fakeMLS) CreateGroup(_ context.Context, req GroupRequest) (Group, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.requests = append(m.requests, req)
	return &fakeGroup{req: req, epoch: 1}, nil
}

type call struct {
	httpMethod string
	url        string
	header     http.Header
	id         string
	method     string
	params     json.RawMessage
}

// fakeERDS answers the sender's requests and records them.
type fakeERDS struct {
	t   *testing.T
	srv *httptest.Server

	mu            sync.Mutex
	calls         []call
	recipients    map[string][]mls.KeyPackage
	security      string
	capabilities  string
	refuse        map[string]*wmp.RPCError
	resolveAnswer map[string]string
	evidencePages []string
	evidenceReads int
	resolves      int
}

func newFakeERDS(t *testing.T) *fakeERDS {
	e := &fakeERDS{
		t:             t,
		recipients:    map[string][]mls.KeyPackage{bob: {{CipherSuite: 2, KeyPackage: "a3AtYm9i"}}},
		security:      `{"mode":"mls","cipher_suites":[1,2]}`,
		refuse:        map[string]*wmp.RPCError{},
		resolveAnswer: map[string]string{},
		evidencePages: []string{`{"evidence_records":[]}`},
	}
	e.srv = httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *fakeERDS) endpoint() string { return e.srv.URL + "/wmp" }

func (e *fakeERDS) serve(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	target := e.srv.URL + r.URL.RequestURI()
	if r.Method == http.MethodGet {
		e.calls = append(e.calls, call{httpMethod: r.Method, url: target, header: r.Header.Clone()})
		i := e.evidenceReads
		if i >= len(e.evidencePages) {
			i = len(e.evidencePages) - 1
		}
		e.evidenceReads++
		_, _ = io.WriteString(w, e.evidencePages[i])
		return
	}
	var req struct {
		ID     string          `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		e.t.Errorf("request body: %v", err)
	}
	e.calls = append(e.calls, call{httpMethod: r.Method, url: target, header: r.Header.Clone(), id: req.ID, method: req.Method, params: req.Params})
	answer := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	if refused := e.refuse[req.Method]; refused != nil {
		answer["error"] = refused
	} else {
		answer["result"] = json.RawMessage(e.result(req.Method, req.Params))
	}
	_ = json.NewEncoder(w).Encode(answer)
}

func (e *fakeERDS) result(method string, params json.RawMessage) string {
	switch method {
	case wmp.MethodSessionCreate:
		caps := e.capabilities
		if caps == "" {
			caps = `{}`
		}
		return `{"wmp":{"version":"0.1","session_id":"` + sid + `"},"security":` + e.security + `,"capabilities":` + caps + `}`
	case wmp.MethodResolve:
		var p wmp.ResolveParams
		_ = json.Unmarshal(params, &p)
		if a, ok := e.resolveAnswer[p.Type]; ok {
			return a
		}
		if p.Type == "participant" {
			return `{"type":"participant","resolved":true,"qerds_capable":true}`
		}
		e.resolves++
		kps, _ := json.Marshal(map[string]any{"type": p.Type, "uri": p.URI, "key_packages": e.recipients[p.URI]})
		return string(kps)
	}
	return `{"wmp":{"version":"0.1","session_id":"` + sid + `"}}`
}

func (e *fakeERDS) of(method string) []call {
	var out []call
	for _, c := range e.calls {
		if c.method == method {
			out = append(out, c)
		}
	}
	return out
}

func (e *fakeERDS) methods() []string {
	var out []string
	for _, c := range e.calls {
		out = append(out, c.method)
	}
	return out
}

type credentialFixture struct {
	roots *x509.CertPool
	cred  Credential
	x5c   []string
}

func newCredential(t *testing.T) *credentialFixture {
	t.Helper()
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "sender"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	signer, err := proof.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &credentialFixture{
		roots: pool,
		cred:  Credential{Chain: []*x509.Certificate{leaf, ca}, Signer: signer},
		x5c:   []string{base64.StdEncoding.EncodeToString(leaf.Raw), base64.StdEncoding.EncodeToString(ca.Raw)},
	}
}

type env struct {
	erds *fakeERDS
	mls  *fakeMLS
	cred *credentialFixture
	cfg  Config
}

func setup(t *testing.T) *env {
	t.Helper()
	e := &env{erds: newFakeERDS(t), mls: &fakeMLS{}, cred: newCredential(t)}
	e.cfg = Config{
		Endpoint:   e.erds.endpoint(),
		Sender:     sender,
		Recipients: []string{bob},
		Credential: e.cred.cred,
		Message:    Message{Body: json.RawMessage(`{"text":"the consignment"}`)},
		Evidence:   Evidence{Skip: true},
		MLS:        e.mls,
	}
	return e
}

func decode(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%s: %v", raw, err)
	}
	return m
}

func keys(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func stepOf(err error) Step {
	var e *Error
	if errors.As(err, &e) {
		return e.Step
	}
	return ""
}

func TestSendRunsTheConsignment(t *testing.T) {
	e := setup(t)
	res, err := Send(context.Background(), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{wmp.MethodSessionCreate, wmp.MethodResolve, wmp.MethodResolve, mls.MethodGroupCreate, wmp.MethodMessageDeliver}
	if got := e.erds.methods(); !reflect.DeepEqual(got, want) {
		t.Fatalf("methods %v", got)
	}

	create := e.erds.calls[0]
	if create.header.Get("Wmp-Session-Id") != "" || create.header.Get("Authorization") != "" {
		t.Fatalf("create headers %v", create.header)
	}
	var cp struct {
		WMP          wmp.Metadata               `json:"wmp"`
		Participants []string                   `json:"participants"`
		Auth         wmp.AuthObject             `json:"auth"`
		Security     wmp.SecurityMode           `json:"security"`
		TTL          int                        `json:"ttl"`
		Caps         map[string]json.RawMessage `json:"capabilities_offered"`
	}
	if err := json.Unmarshal(create.params, &cp); err != nil {
		t.Fatal(err)
	}
	host := strings.Split(strings.TrimPrefix(e.erds.srv.URL, "http://"), ":")[0]
	if cp.WMP.SessionID != "" || cp.WMP.Sender != sender || cp.WMP.Timestamp == nil ||
		!reflect.DeepEqual(cp.Participants, []string{"x509:san:dns:" + host}) ||
		cp.Auth.Type != "mtls" || cp.Security.Mode != "mls" || !reflect.DeepEqual(cp.Security.CipherSuites, []int{1, 2}) || cp.TTL != 3600 {
		t.Fatalf("create params %s", create.params)
	}
	if !strings.Contains(string(cp.Caps["evidence"]), "delivery_confirmed") {
		t.Fatalf("capabilities %s", create.params)
	}

	for _, c := range e.erds.calls[1:] {
		var p struct {
			WMP wmp.Metadata `json:"wmp"`
		}
		_ = json.Unmarshal(c.params, &p)
		if c.header.Get("Wmp-Session-Id") != sid || p.WMP.SessionID != sid || c.url != e.erds.endpoint() {
			t.Fatalf("%s is not in the session: %v %s", c.method, c.header, c.params)
		}
	}
	var types []string
	for _, c := range e.erds.of(wmp.MethodResolve) {
		var p wmp.ResolveParams
		_ = json.Unmarshal(c.params, &p)
		types = append(types, p.Type+" "+p.URI)
	}
	if !reflect.DeepEqual(types, []string{"participant " + bob, "mls_key_packages " + bob}) {
		t.Fatalf("resolves %v", types)
	}

	var gp mls.GroupCreateParams
	_ = json.Unmarshal(e.erds.of(mls.MethodGroupCreate)[0].params, &gp)
	if gp.GroupID != "Z3JvdXAtMQ" || gp.CipherSuite != 2 || gp.GroupInfo != "Z3JvdXAtaW5mbw" || len(gp.Welcomes) != 1 || gp.Welcomes[bob] == "" {
		t.Fatalf("group create %+v", gp)
	}
	// The MLS engine gets the sender's chain as the leaf credential and the
	// KeyPackage that was resolved for the recipient.
	req := e.mls.requests[0]
	if len(req.Certificates) != 2 || string(req.Certificates[0]) != string(e.cred.cred.Chain[0].Raw) || req.KeyPackages[bob].KeyPackage != "a3AtYm9i" {
		t.Fatalf("group request %+v", req)
	}
	if res.SessionID != sid || res.GroupID != gp.GroupID || res.CipherSuite != 2 || res.Epoch != 1 || res.Confirmed {
		t.Fatalf("result %+v", res)
	}
}

func TestDeliverIsCiphertextOnlySignedAndAsserted(t *testing.T) {
	e := setup(t)
	res, err := Send(context.Background(), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := e.erds.of(wmp.MethodMessageDeliver)[0]
	params := decode(t, c.params)
	if got := keys(params); !reflect.DeepEqual(got, []string{"ciphertext", "wmp"}) {
		t.Fatalf("deliver params have members %v", got)
	}
	var meta wmp.Metadata
	if err := json.Unmarshal(params["wmp"], &meta); err != nil {
		t.Fatal(err)
	}
	if !meta.Encrypted || meta.Epoch == nil || *meta.Epoch != 1 || meta.Sender != sender || meta.SessionID != sid {
		t.Fatalf("wmp %s", params["wmp"])
	}
	if len(meta.IdentityAssertions) != 1 || meta.IdentityAssertions[0].Type != "x509_chain" || !reflect.DeepEqual(meta.IdentityAssertions[0].X5C, e.cred.x5c) {
		t.Fatalf("identity assertions %+v", meta.IdentityAssertions)
	}
	if c.id != res.Message.ID || meta.Signature != res.Message.Signature {
		t.Fatalf("result message %+v", res.Message)
	}

	// The signature covers params without wmp, and chains to the credential.
	content, err := signature.ContentObject(c.params)
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&signature.Verifier{Roots: e.cred.roots}).Verify(meta.Signature, content)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Chain[0].Equal(e.cred.cred.Chain[0]) {
		t.Fatal("signed with another certificate")
	}
	canonical, _ := jcs.Canonicalize(content)
	if string(res.Message.Content) != string(canonical) {
		t.Fatalf("result content %s, sent %s", res.Message.Content, canonical)
	}

	// What was encrypted is the plaintext content object.
	var ciphertext string
	_ = json.Unmarshal(params["ciphertext"], &ciphertext)
	plaintext, _ := b64u.DecodeString(ciphertext)
	want := `{"body":{"text":"the consignment"},"content_type":"application/json","to":["` + bob + `"]}`
	if string(plaintext) != want || string(res.Message.Plaintext) != want {
		t.Fatalf("plaintext %s", plaintext)
	}
}

func TestUniqueIDsAndAFreshKeyPackagePerSend(t *testing.T) {
	e := setup(t)
	first, err := Send(context.Background(), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Send(context.Background(), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if first.Message.ID == second.Message.ID {
		t.Fatal("the message id was reused")
	}
	if e.erds.resolves != 2 {
		t.Fatalf("KeyPackages resolved %d times for 2 groups", e.erds.resolves)
	}
	seen := map[string]bool{}
	for _, c := range e.erds.calls {
		if seen[c.id] {
			t.Fatalf("request id %s was reused", c.id)
		}
		seen[c.id] = true
	}
	e.cfg.Message.ID = "msg-mine"
	third, err := Send(context.Background(), e.cfg)
	if err != nil || third.Message.ID != "msg-mine" {
		t.Fatalf("got %v, %v", third, err)
	}
}

func TestDPoPProvesEveryRequest(t *testing.T) {
	e := setup(t)
	e.cfg.Auth = wmp.AuthTypeDPoP
	e.cfg.Evidence = Evidence{Timeout: time.Nanosecond}
	if _, err := Send(context.Background(), e.cfg); err != nil {
		t.Fatal(err)
	}
	if len(e.erds.calls) != 6 {
		t.Fatalf("%d requests", len(e.erds.calls))
	}
	if !strings.Contains(string(e.erds.calls[0].params), `"auth":{"type":"dpop"}`) {
		t.Fatalf("create %s", e.erds.calls[0].params)
	}
	v := &proof.Verifier{Roots: e.cred.roots, Replay: proof.NewMemoryReplayCache()}
	for i, c := range e.erds.calls {
		compact, ok := proof.FromHeader(c.header.Get("Authorization"))
		if !ok {
			t.Fatalf("request %d carries no proof", i)
		}
		want := proof.Expect{Method: c.httpMethod, URL: c.url, SessionID: sid}
		if i == 0 {
			want = proof.Expect{Method: c.httpMethod, URL: c.url, NoSession: true}
		}
		if _, err := v.Verify(compact, want); err != nil {
			t.Fatalf("request %d (%s %s): %v", i, c.httpMethod, c.url, err)
		}
	}
	// The evidence read is proved as the GET it is, on the repository URL.
	last := e.erds.calls[5]
	if last.httpMethod != http.MethodGet || last.url != e.erds.endpoint()+"/evidence?session_id="+sid {
		t.Fatalf("evidence read %s %s", last.httpMethod, last.url)
	}
}

func TestPlaintextHash(t *testing.T) {
	e := setup(t)
	e.cfg.PlaintextHash = true
	res, err := Send(context.Background(), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := e.erds.of(wmp.MethodMessageDeliver)[0]
	params := decode(t, c.params)
	if got := keys(params); !reflect.DeepEqual(got, []string{"ciphertext", "plaintext_hash", "wmp"}) {
		t.Fatalf("deliver params have members %v", got)
	}
	var ciphertext string
	_ = json.Unmarshal(params["ciphertext"], &ciphertext)
	plaintext, _ := b64u.DecodeString(ciphertext)
	var plain struct {
		Salt string `json:"salt"`
	}
	_ = json.Unmarshal(plaintext, &plain)
	if salt, err := b64u.DecodeString(plain.Salt); err != nil || len(salt) < 16 {
		t.Fatalf("salt %q", plain.Salt)
	}
	canonical, err := jcs.Canonicalize(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	want := `{"algorithm":"sha-256","value":"` + b64u.EncodeToString(digest[:]) + `"}`
	if string(params["plaintext_hash"]) != want {
		t.Fatalf("plaintext_hash %s, want %s", params["plaintext_hash"], want)
	}
	// The signature covers the commitment.
	var meta wmp.Metadata
	_ = json.Unmarshal(params["wmp"], &meta)
	v := &signature.Verifier{Roots: e.cred.roots}
	if _, err := v.Verify(meta.Signature, res.Message.Content); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(meta.Signature, []byte(`{"ciphertext":"`+ciphertext+`"}`)); !errors.Is(err, signature.ErrInvalid) {
		t.Fatalf("the signature does not cover plaintext_hash: %v", err)
	}
}

func TestSeveralRecipientsShareOneGroup(t *testing.T) {
	e := setup(t)
	e.cfg.Recipients = []string{bob, carol}
	e.erds.recipients[bob] = []mls.KeyPackage{{CipherSuite: 1, KeyPackage: "Ym9iLTE"}, {CipherSuite: 2, KeyPackage: "Ym9iLTI"}}
	e.erds.recipients[carol] = []mls.KeyPackage{{CipherSuite: 2, KeyPackage: "Y2Fyb2wtMg"}}
	res, err := Send(context.Background(), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := e.mls.requests[0]
	if res.CipherSuite != 2 || req.KeyPackages[bob].KeyPackage != "Ym9iLTI" || req.KeyPackages[carol].KeyPackage != "Y2Fyb2wtMg" {
		t.Fatalf("suite %d, request %+v", res.CipherSuite, req)
	}
	var gp mls.GroupCreateParams
	_ = json.Unmarshal(e.erds.of(mls.MethodGroupCreate)[0].params, &gp)
	if len(gp.Welcomes) != 2 {
		t.Fatalf("welcomes %v", gp.Welcomes)
	}
	if !strings.Contains(string(res.Message.Plaintext), `"to":["`+bob+`","`+carol+`"]`) {
		t.Fatalf("plaintext %s", res.Message.Plaintext)
	}
}

func TestSuiteComesFromTheKeyPackageWithinTheSession(t *testing.T) {
	e := setup(t)
	e.erds.recipients[bob] = []mls.KeyPackage{{CipherSuite: 1, KeyPackage: "Ym9iLTE"}}
	res, err := Send(context.Background(), e.cfg)
	if err != nil || res.CipherSuite != 1 {
		t.Fatalf("got %+v, %v", res, err)
	}
	e.erds.security = `{"mode":"mls","cipher_suite":2}`
	if _, err := Send(context.Background(), e.cfg); stepOf(err) != StepGroup {
		t.Fatalf("a suite the session does not accept: %v", err)
	}
	if n := len(e.erds.of(wmp.MethodMessageDeliver)); n != 1 {
		t.Fatalf("%d delivers", n)
	}
}

func TestResolveRefusals(t *testing.T) {
	cases := map[string][2]string{
		"not QERDS-capable":           {"participant", `{"resolved":true,"qerds_capable":false}`},
		"without qerds_capable":       {"participant", `{"resolved":true}`},
		"null qerds_capable":          {"participant", `{"resolved":true,"qerds_capable":null}`},
		"unresolved":                  {"participant", `{"resolved":false,"qerds_capable":true}`},
		"null metadata":               {"participant", `{"metadata":null}`},
		"without KeyPackages":         {"mls_key_packages", `{"key_packages":[]}`},
		"null KeyPackages":            {"mls_key_packages", `{"key_packages":null}`},
		"a KeyPackage without a body": {"mls_key_packages", `{"key_packages":[{"cipher_suite":2,"key_package":null}]}`},
		"a KeyPackage without suite":  {"mls_key_packages", `{"key_packages":[{"cipher_suite":null,"key_package":"a3A"}]}`},
	}
	for name, c := range cases {
		e := setup(t)
		e.erds.resolveAnswer[c[0]] = c[1]
		if _, err := Send(context.Background(), e.cfg); stepOf(err) != StepResolve {
			t.Errorf("%s: got %v", name, err)
		}
		if len(e.erds.of(mls.MethodGroupCreate)) != 0 || len(e.erds.of(wmp.MethodMessageDeliver)) != 0 || len(e.mls.requests) != 0 {
			t.Errorf("%s: the flow went on", name)
		}
	}
}

func TestResolveAnswerInMetadata(t *testing.T) {
	e := setup(t)
	e.erds.resolveAnswer["participant"] = `{"type":"participant","metadata":{"resolved":true,"qerds_capable":true}}`
	e.erds.resolveAnswer["mls_key_packages"] = `{"type":"mls_key_packages","metadata":{"key_packages":[{"cipher_suite":2,"key_package":"a3A"}]}}`
	res, err := Send(context.Background(), e.cfg)
	if err != nil || res.CipherSuite != 2 {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestRefusedRequestNamesItsStep(t *testing.T) {
	cases := map[string]Step{
		wmp.MethodSessionCreate:  StepSession,
		wmp.MethodResolve:        StepResolve,
		mls.MethodGroupCreate:    StepGroup,
		wmp.MethodMessageDeliver: StepDeliver,
	}
	for method, step := range cases {
		e := setup(t)
		e.erds.refuse[method] = &wmp.RPCError{Code: -31010, Message: "Signature invalid"}
		_, err := Send(context.Background(), e.cfg)
		var rpc *wmp.RPCError
		if stepOf(err) != step || !errors.As(err, &rpc) || rpc.Code != -31010 {
			t.Errorf("%s: got %v", method, err)
		}
		if last := e.erds.calls[len(e.erds.calls)-1]; last.method != method {
			t.Errorf("%s: the flow went on to %s", method, last.method)
		}
	}
}

func TestMLSEngineFailureIsAGroupError(t *testing.T) {
	e := setup(t)
	e.mls.err = errors.New("no such suite")
	if _, err := Send(context.Background(), e.cfg); stepOf(err) != StepGroup {
		t.Fatalf("got %v", err)
	}
	if len(e.erds.of(mls.MethodGroupCreate)) != 0 {
		t.Fatal("a group was registered")
	}
}

func rec(id, typ, msg string) string {
	return `{"evidence_id":"` + id + `","event_type":"` + typ + `","original_message_id":"` + msg + `"}`
}

func TestEvidencePoll(t *testing.T) {
	e := setup(t)
	e.cfg.Message.ID = "msg-1"
	e.cfg.Evidence = Evidence{Interval: time.Millisecond, Timeout: 5 * time.Second}
	e.erds.evidencePages = []string{
		`{"evidence_records":[` + rec("evi-1", "submission_accepted", "msg-1") + `,` + rec("evi-x", "delivery_confirmed", "msg-other") + `]}`,
		`{"evidence_records":[` + rec("evi-1", "submission_accepted", "msg-1") + `],"continuation_token":"page-2"}`,
		`{"evidence_records":[` + rec("evi-2", "delivery_confirmed", "msg-1") + `],"continuation_token":null}`,
	}
	res, err := Send(context.Background(), e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Confirmed || len(res.Evidence) != 2 || res.Evidence[0].EvidenceID != "evi-1" || res.Evidence[1].EvidenceID != "evi-2" {
		t.Fatalf("evidence %+v confirmed %v", res.Evidence, res.Confirmed)
	}
	if string(res.Evidence[1].Raw) != rec("evi-2", "delivery_confirmed", "msg-1") {
		t.Fatalf("raw %s", res.Evidence[1].Raw)
	}
	var gets []string
	for _, c := range e.erds.calls {
		if c.httpMethod == http.MethodGet {
			gets = append(gets, strings.TrimPrefix(c.url, e.erds.endpoint()))
			if c.header.Get("Wmp-Session-Id") != sid {
				t.Fatal("an evidence read outside the session")
			}
		}
	}
	want := []string{"/evidence?session_id=" + sid, "/evidence?session_id=" + sid, "/evidence?continuation_token=page-2&session_id=" + sid}
	if !reflect.DeepEqual(gets, want) {
		t.Fatalf("reads %v", gets)
	}
}

func TestEvidencePollEndsUnconfirmed(t *testing.T) {
	e := setup(t)
	e.cfg.Message.ID = "msg-1"
	e.cfg.Evidence = Evidence{Interval: time.Millisecond, Timeout: 20 * time.Millisecond}
	e.erds.evidencePages = []string{`{"evidence_records":[` + rec("evi-1", "submission_accepted", "msg-1") + `]}`}
	res, err := Send(context.Background(), e.cfg)
	if err != nil || res.Confirmed || len(res.Evidence) != 1 {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestEvidenceRepositoryFromTheSession(t *testing.T) {
	e := setup(t)
	e.cfg.Evidence = Evidence{Timeout: time.Nanosecond}
	e.erds.capabilities = `{"evidence":{"repository":"` + e.erds.srv.URL + `/api/"}}`
	if _, err := Send(context.Background(), e.cfg); err != nil {
		t.Fatal(err)
	}
	if last := e.erds.calls[len(e.erds.calls)-1]; last.url != e.erds.srv.URL+"/api/evidence?session_id="+sid {
		t.Fatalf("read %s", last.url)
	}
}

func TestEvidenceRefusesMalformedAnswers(t *testing.T) {
	for name, page := range map[string]string{
		"null evidence_records": `{"evidence_records":null}`,
		"no evidence_records":   `{}`,
		"a record without id":   `{"evidence_records":[{"event_type":"delivery_confirmed"}]}`,
		"a null record":         `{"evidence_records":[null]}`,
		"not JSON":              `nope`,
	} {
		e := setup(t)
		e.cfg.Evidence = Evidence{Timeout: time.Nanosecond}
		e.erds.evidencePages = []string{page}
		res, err := Send(context.Background(), e.cfg)
		if stepOf(err) != StepEvidence {
			t.Errorf("%s: got %v", name, err)
		}
		if res == nil || res.Message.ID == "" || res.Confirmed {
			t.Errorf("%s: the result does not carry what was sent: %+v", name, res)
		}
	}
}

func TestConfigIsCheckedBeforeAnyRequest(t *testing.T) {
	cases := map[string]func(c *Config){
		"a relative endpoint":     func(c *Config) { c.Endpoint = "/wmp" },
		"no sender":               func(c *Config) { c.Sender = "" },
		"no recipients":           func(c *Config) { c.Recipients = nil },
		"an empty recipient":      func(c *Config) { c.Recipients = []string{""} },
		"a repeated recipient":    func(c *Config) { c.Recipients = []string{bob, bob} },
		"an empty chain":          func(c *Config) { c.Credential.Chain = nil },
		"no signer":               func(c *Config) { c.Credential.Signer = nil },
		"an unknown auth":         func(c *Config) { c.Auth = "bearer" },
		"no body":                 func(c *Config) { c.Message.Body = nil },
		"a null body":             func(c *Config) { c.Message.Body = json.RawMessage(`null`) },
		"a body that is not JSON": func(c *Config) { c.Message.Body = json.RawMessage(`{`) },
		"no MLS engine":           func(c *Config) { c.MLS = nil },
	}
	for name, edit := range cases {
		e := setup(t)
		edit(&e.cfg)
		if _, err := Send(context.Background(), e.cfg); stepOf(err) != StepConfig {
			t.Errorf("%s: got %v", name, err)
		}
		if len(e.erds.calls) != 0 {
			t.Errorf("%s: a request was made", name)
		}
	}
}
