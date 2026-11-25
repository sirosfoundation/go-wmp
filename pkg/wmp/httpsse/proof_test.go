package httpsse

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/proof"
)

type proofPKI struct {
	roots *x509.CertPool
	ca    *x509.Certificate
	key   *ecdsa.PrivateKey
}

func newProofPKI(t *testing.T) *proofPKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &proofPKI{roots: pool, ca: ca, key: key}
}

// wallet returns a Creator whose leaf certificate names san.
func (p *proofPKI) wallet(t *testing.T, san string) *proof.Creator {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(san)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "wallet"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	signer, _ := proof.NewSigner(key)
	return &proof.Creator{Signer: signer, Chain: []*x509.Certificate{leaf, p.ca}}
}

// The create is authenticated as "Bearer <san>" and the proofs as the SAN of
// the leaf, so a wallet's proofs act on the sessions its bearer created.
func newProofFixture(t *testing.T) (*securedFixture, *proofPKI) {
	t.Helper()
	pki := newProofPKI(t)
	f := newSecuredFixture(t, func(cfg *ServerConfig) {
		cfg.Proof = &ProofConfig{
			Verifier: &proof.Verifier{Roots: pki.roots, Replay: proof.NewMemoryReplayCache()},
			Principal: func(p *proof.Proof) (wmp.Principal, error) {
				if len(p.Chain) == 0 || len(p.Chain[0].URIs) != 1 {
					return wmp.Principal{}, errors.New("no identity")
				}
				return wmp.Principal{Subject: p.Chain[0].URIs[0].String()}, nil
			},
		}
	})
	return f, pki
}

func (f *securedFixture) proofFor(c *proof.Creator, method, path, sid string) string {
	f.t.Helper()
	p, err := c.Proof(proof.Request{Method: method, URL: f.ts.URL + path, SessionID: sid})
	if err != nil {
		f.t.Fatal(err)
	}
	return "DPoP " + p
}

// pingBody is a request the session's handler answers "method not found":
// that answer shows the request was admitted to the session.
func pingBody(sid string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0", "id": "p1", "method": wmp.MethodCapabilityList,
		"params": map[string]any{"wmp": map[string]any{"version": wmp.Version, "sender": "x", "session_id": sid}},
	}
}

func TestProofRequiredOnSessionRequests(t *testing.T) {
	f, pki := newProofFixture(t)
	const alice = "https://alice.example.com"
	wallet := pki.wallet(t, alice)
	id, _ := f.create("Bearer " + alice)

	if r := f.post(f.proofFor(wallet, "POST", "", id), nil, pingBody(id)); r.Status != http.StatusOK || rpcCode(r) != wmp.ErrMethodNotFound {
		t.Fatalf("valid proof: %d %s", r.Status, r.Raw)
	}
	// The bearer that created the session does not act on it without a proof.
	if r := f.post("Bearer "+alice, nil, pingBody(id)); r.Status != http.StatusUnauthorized {
		t.Fatalf("no proof: %d %s", r.Status, r.Raw)
	}
	if r := f.post("", nil, pingBody(id)); r.Status != http.StatusUnauthorized {
		t.Fatalf("no credential: %d", r.Status)
	}
}

func TestProofMustNameTheSessionMethodAndURL(t *testing.T) {
	f, pki := newProofFixture(t)
	const alice = "https://alice.example.com"
	wallet := pki.wallet(t, alice)
	id, _ := f.create("Bearer " + alice)
	other, _ := f.create("Bearer " + alice)

	for name, auth := range map[string]string{
		"another session": f.proofFor(wallet, "POST", "", other),
		"another method":  f.proofFor(wallet, "GET", "", id),
		"another url":     f.proofFor(wallet, "POST", "/events", id),
		"garbage":         "DPoP a.b.c",
	} {
		if r := f.post(auth, nil, pingBody(id)); r.Status != http.StatusUnauthorized {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	// An untrusted chain.
	stranger := newProofPKI(t).wallet(t, alice)
	if r := f.post(f.proofFor(stranger, "POST", "", id), nil, pingBody(id)); r.Status != http.StatusUnauthorized {
		t.Errorf("untrusted chain: %d", r.Status)
	}
}

// A proof is bound to an existing session: it does not create one, whatever
// session it names.
func TestProofDoesNotCreateASession(t *testing.T) {
	f, pki := newProofFixture(t)
	wallet := pki.wallet(t, "https://alice.example.com")
	count := func() int { l, _ := f.store.List(); return len(l) }
	before := count()
	if r := f.post(f.proofFor(wallet, "POST", "", "ses-made-up"), nil, createBody("c1")); r.Status != http.StatusUnauthorized {
		t.Fatalf("%d %s", r.Status, r.Raw)
	}
	if got := count(); got != before {
		t.Fatalf("sessions: %d, want %d", got, before)
	}
}

func TestProofIsSingleUse(t *testing.T) {
	f, pki := newProofFixture(t)
	const alice = "https://alice.example.com"
	id, _ := f.create("Bearer " + alice)
	auth := f.proofFor(pki.wallet(t, alice), "POST", "", id)
	if r := f.post(auth, nil, pingBody(id)); r.Status != http.StatusOK || rpcCode(r) != wmp.ErrMethodNotFound {
		t.Fatalf("first use: %d", r.Status)
	}
	if r := f.post(auth, nil, pingBody(id)); r.Status != http.StatusUnauthorized {
		t.Fatalf("replay: %d", r.Status)
	}
}

func TestProofOfAnotherIdentityFindsNoSession(t *testing.T) {
	f, pki := newProofFixture(t)
	id, _ := f.create("Bearer https://alice.example.com")
	mallory := pki.wallet(t, "https://mallory.example.com")
	r := f.post(f.proofFor(mallory, "POST", "", id), nil, pingBody(id))
	if r.Status != http.StatusOK || rpcCode(r) != wmp.ErrSessionNotFound {
		t.Fatalf("%d %s", r.Status, r.Raw)
	}
}

func TestProofOnTheEventStream(t *testing.T) {
	f, pki := newProofFixture(t)
	const alice = "https://alice.example.com"
	wallet := pki.wallet(t, alice)
	id, _ := f.create("Bearer " + alice)

	if resp := f.get("Bearer "+alice, "session_id="+id, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no proof: %d", resp.StatusCode)
	}
	if resp := f.get(f.proofFor(wallet, "GET", "/events", "ses-other"), "session_id="+id, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("another session: %d", resp.StatusCode)
	}
	if resp := f.get(f.proofFor(wallet, "GET", "/events", id), "session_id="+id, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("valid proof: %d", resp.StatusCode)
	}
}

func TestProofURLOverride(t *testing.T) {
	pki := newProofPKI(t)
	const alice = "https://alice.example.com"
	f := newSecuredFixture(t, func(cfg *ServerConfig) {
		cfg.Proof = &ProofConfig{
			Verifier:  &proof.Verifier{Roots: pki.roots},
			Principal: func(*proof.Proof) (wmp.Principal, error) { return wmp.Principal{Subject: alice}, nil },
			URL:       func(r *http.Request) string { return "https://relay.example.com/wmp" },
		}
	})
	wallet := pki.wallet(t, alice)
	id, _ := f.create("Bearer " + alice)
	p, _ := wallet.Proof(proof.Request{Method: "POST", URL: "https://relay.example.com/wmp", SessionID: id})
	if r := f.post("DPoP "+p, nil, pingBody(id)); r.Status != http.StatusOK || rpcCode(r) != wmp.ErrMethodNotFound {
		t.Fatalf("public url: %d %s", r.Status, r.Raw)
	}
	if r := f.post(f.proofFor(wallet, "POST", "", id), nil, pingBody(id)); r.Status != http.StatusUnauthorized {
		t.Fatalf("internal url: %d", r.Status)
	}
}

func TestProofConfigWithoutVerifierFailsClosed(t *testing.T) {
	pki := newProofPKI(t)
	const alice = "https://alice.example.com"
	f := newSecuredFixture(t, func(cfg *ServerConfig) { cfg.Proof = &ProofConfig{} })
	id, _ := f.create("Bearer " + alice)
	if r := f.post(f.proofFor(pki.wallet(t, alice), "POST", "", id), nil, pingBody(id)); r.Status != http.StatusUnauthorized {
		t.Fatalf("%d", r.Status)
	}
}

// The client transport proves each request that names a session and leaves
// the create, which names none, to the configured headers.
func TestClientTransportSendsProofs(t *testing.T) {
	f, pki := newProofFixture(t)
	const alice = "https://alice.example.com"
	tr, err := NewClientTransport(f.ts.URL,
		WithInsecure(true),
		WithHeaders(http.Header{"Authorization": {"Bearer " + alice}}),
		WithProof(pki.wallet(t, alice)))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	roundTrip := func(body map[string]any) map[string]any {
		t.Helper()
		b, _ := json.Marshal(body)
		if err := tr.WriteMessage(ctx, b); err != nil {
			t.Fatal(err)
		}
		raw, err := tr.ReadMessage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		_ = json.NewDecoder(bytes.NewReader(raw)).Decode(&out)
		return out
	}
	created := roundTrip(createBody("c1"))
	res, _ := created["result"].(map[string]any)
	if res == nil {
		t.Fatalf("create: %v", created)
	}
	id, _ := res["wmp"].(map[string]any)["session_id"].(string)
	if pong := roundTrip(pingBody(id)); pong["error"].(map[string]any)["code"] != float64(wmp.ErrMethodNotFound) {
		t.Fatalf("ping: %v", pong)
	}
	if err := tr.ConnectSSE(ctx, id); err != nil {
		t.Fatalf("event stream: %v", err)
	}
}
