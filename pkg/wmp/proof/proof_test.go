package proof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

var epoch = time.Unix(1795526400, 0)

type pki struct {
	roots *x509.CertPool
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: epoch.Add(-time.Hour), NotAfter: epoch.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &pki{roots: pool, ca: ca, caKey: key}
}

func (p *pki) leaf(t *testing.T, pub crypto.PublicKey, san string) *x509.Certificate {
	t.Helper()
	u, _ := url.Parse(san)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "wallet"},
		NotBefore: epoch.Add(-time.Hour), NotAfter: epoch.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, pub, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func fixedNow() time.Time { return epoch }

type fixture struct {
	pki      *pki
	creator  *Creator
	verifier *Verifier
	req      Request
	want     Expect
}

func newFixture(t *testing.T, curve elliptic.Curve) *fixture {
	t.Helper()
	p := newPKI(t)
	key, _ := ecdsa.GenerateKey(curve, rand.Reader)
	signer, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		pki:      p,
		creator:  &Creator{Signer: signer, Chain: []*x509.Certificate{p.leaf(t, &key.PublicKey, "https://wallet.example.com"), p.ca}, Now: fixedNow},
		verifier: &Verifier{Roots: p.roots, Now: fixedNow},
		req:      Request{Method: "POST", URL: "https://relay.example.com/wmp", SessionID: "ses-a1b2c3d4"},
		want:     Expect{Method: "POST", URL: "https://relay.example.com/wmp", SessionID: "ses-a1b2c3d4"},
	}
}

func (f *fixture) proof(t *testing.T) string {
	t.Helper()
	p, err := f.creator.Proof(f.req)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The payload of the specification's example (WMP Core section 4.4.8).
func TestCanonicalPayloadMatchesTheSpecExample(t *testing.T) {
	c := Claims{Method: "POST", URL: "https://relay.example.com/wmp", IssuedAt: 1795526400, ID: "proof-8f4b2c1d", SessionID: "ses-a1b2c3d4"}
	got, err := c.canonical()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"htm":"POST","htu":"https://relay.example.com/wmp","iat":1795526400,"jti":"proof-8f4b2c1d","sid":"ses-a1b2c3d4"}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestCanonicalStringEscaping(t *testing.T) {
	got := string(appendJCSString(nil, "a\"\\\n\x01<é "))
	want := "\"a\\\"\\\\\\n\\u0001<é \""
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestProofShape(t *testing.T) {
	f := newFixture(t, elliptic.P256())
	parts := strings.Split(f.proof(t), ".")
	if len(parts) != 3 {
		t.Fatalf("segments: %d", len(parts))
	}
	raw, _ := b64.DecodeString(parts[0])
	var hdr struct {
		Alg, Typ string
		X5C      []string `json:"x5c"`
		Kid      *string  `json:"kid"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Alg != "ES256" || hdr.Typ != "wmp-proof+jwt" || len(hdr.X5C) != 2 || hdr.Kid != nil {
		t.Fatalf("header %s", raw)
	}
	payload, _ := b64.DecodeString(parts[1])
	if !strings.HasPrefix(string(payload), `{"htm":"POST","htu":"https://relay.example.com/wmp","iat":1795526400,"jti":"`) ||
		!strings.HasSuffix(string(payload), `","sid":"ses-a1b2c3d4"}`) {
		t.Fatalf("payload %s", payload)
	}
}

func TestRoundTrip(t *testing.T) {
	for name, curve := range map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, curve)
			p, err := f.verifier.Verify(f.proof(t), f.want)
			if err != nil {
				t.Fatal(err)
			}
			if p.Algorithm != name || p.SessionID != "ses-a1b2c3d4" || len(p.Chain) != 2 ||
				p.Chain[0].URIs[0].String() != "https://wallet.example.com" || p.ID == "" {
				t.Fatalf("proof %+v", p)
			}
		})
	}
}

func TestRoundTripKid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := NewSigner(priv)
	c := &Creator{Signer: signer, KeyID: "did:web:wallet.example.com#key-1", Now: fixedNow}
	v := &Verifier{Now: fixedNow, ResolveKey: func(kid string) (crypto.PublicKey, error) {
		if kid != "did:web:wallet.example.com#key-1" {
			return nil, errors.New("unknown")
		}
		return pub, nil
	}}
	req := Request{Method: "GET", URL: "https://relay.example.com/wmp/events?session_id=s1", SessionID: "s1"}
	compact, err := c.Proof(req)
	if err != nil {
		t.Fatal(err)
	}
	p, err := v.Verify(compact, Expect{Method: "GET", URL: "https://RELAY.example.com:443/wmp/events?session_id=s1", SessionID: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	if p.KeyID != c.KeyID || p.Chain != nil || p.URL != "https://relay.example.com/wmp/events" {
		t.Fatalf("proof %+v", p)
	}
	c.KeyID = "did:web:other.example.com#key-1"
	compact, _ = c.Proof(req)
	if _, err := v.Verify(compact, Expect{Method: "GET", URL: req.URL, SessionID: "s1"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unresolvable kid: %v", err)
	}
}

func TestVerifyRefuses(t *testing.T) {
	cases := map[string]func(f *fixture){
		"another session":  func(f *fixture) { f.want.SessionID = "ses-other" },
		"another method":   func(f *fixture) { f.want.Method = "GET" },
		"another url":      func(f *fixture) { f.want.URL = "https://relay.example.com/other" },
		"another host":     func(f *fixture) { f.want.URL = "https://evil.example.com/wmp" },
		"stale":            func(f *fixture) { f.verifier.Now = func() time.Time { return epoch.Add(31 * time.Second) } },
		"from the future":  func(f *fixture) { f.verifier.Now = func() time.Time { return epoch.Add(-31 * time.Second) } },
		"untrusted chain":  func(f *fixture) { f.verifier.Roots = newPKI(t).roots },
		"no trust anchors": func(f *fixture) { f.verifier.Roots = nil },
		"expired leaf": func(f *fixture) {
			f.creator.Now = func() time.Time { return epoch.Add(2 * time.Hour) }
			f.verifier.Now = f.creator.Now
		},
		"algorithm not allowed": func(f *fixture) { f.verifier.Algorithms = []string{AlgEdDSA} },
		"unexpected token":      func(f *fixture) { f.req.AccessToken = "tok" },
		"missing token hash":    func(f *fixture) { f.want.AccessToken = "tok" },
		"wrong token":           func(f *fixture) { f.req.AccessToken = "tok"; f.want.AccessToken = "tok2" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, elliptic.P256())
			mutate(f)
			if _, err := f.verifier.Verify(f.proof(t), f.want); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestSkewBoundaryAndToken(t *testing.T) {
	f := newFixture(t, elliptic.P256())
	f.verifier.Now = func() time.Time { return epoch.Add(30 * time.Second) }
	if _, err := f.verifier.Verify(f.proof(t), f.want); err != nil {
		t.Fatalf("at the tolerance: %v", err)
	}
	// The access token and its ath of the example in RFC 9449 section 7.1.
	const token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
	f.req.AccessToken, f.want.AccessToken = token, token
	p, err := f.verifier.Verify(f.proof(t), f.want)
	if err != nil {
		t.Fatal(err)
	}
	if p.TokenHash != "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo" {
		t.Fatalf("ath %s", p.TokenHash)
	}
}

func TestUnboundSessionIsReturnedToTheCaller(t *testing.T) {
	f := newFixture(t, elliptic.P256())
	f.want.SessionID = ""
	p, err := f.verifier.Verify(f.proof(t), f.want)
	if err != nil || p.SessionID != "ses-a1b2c3d4" {
		t.Fatalf("%v %+v", err, p)
	}
}

func TestReplayIsRefused(t *testing.T) {
	f := newFixture(t, elliptic.P256())
	f.verifier.Replay = &memoryReplay{seen: map[string]time.Time{}, now: fixedNow}
	compact := f.proof(t)
	if _, err := f.verifier.Verify(compact, f.want); err != nil {
		t.Fatal(err)
	}
	if _, err := f.verifier.Verify(compact, f.want); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replay: %v", err)
	}
	if _, err := f.verifier.Verify(f.proof(t), f.want); err != nil {
		t.Fatalf("fresh proof: %v", err)
	}
}

func TestReplayCacheForgetsExpiredEntries(t *testing.T) {
	now := epoch
	m := &memoryReplay{seen: map[string]time.Time{}, now: func() time.Time { return now }}
	if m.Seen("a", epoch.Add(time.Minute)) || !m.Seen("a", epoch.Add(time.Minute)) {
		t.Fatal("first use must pass and second must not")
	}
	now = epoch.Add(time.Minute)
	if m.Seen("b", now.Add(time.Minute)); len(m.seen) != 1 {
		t.Fatalf("expired entry kept: %v", m.seen)
	}
}

// resign builds a proof from a hand-written header and payload, signed with
// the fixture's key, to present what a Creator never makes.
func (f *fixture) resign(t *testing.T, edit func(header, payload map[string]any)) string {
	t.Helper()
	parts := strings.Split(f.proof(t), ".")
	var header, payload map[string]any
	for i, m := range []*map[string]any{&header, &payload} {
		raw, _ := b64.DecodeString(parts[i])
		if err := json.Unmarshal(raw, m); err != nil {
			t.Fatal(err)
		}
	}
	edit(header, payload)
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig, err := f.creator.Signer.Sign([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64.EncodeToString(sig)
}

func TestVerifyRefusesMalformedProofs(t *testing.T) {
	cases := map[string]func(h, p map[string]any){
		"wrong typ":          func(h, _ map[string]any) { h["typ"] = "dpop+jwt" },
		"no typ":             func(h, _ map[string]any) { delete(h, "typ") },
		"alg none":           func(h, _ map[string]any) { h["alg"] = "none" },
		"alg of another key": func(h, _ map[string]any) { h["alg"] = "ES384" },
		"x5c and kid":        func(h, _ map[string]any) { h["kid"] = "k" },
		"neither":            func(h, _ map[string]any) { delete(h, "x5c") },
		"empty x5c":          func(h, _ map[string]any) { h["x5c"] = []string{} },
		"null x5c":           func(h, _ map[string]any) { h["x5c"] = nil },
		"crit":               func(h, _ map[string]any) { h["crit"] = []string{"x"} },
		"null sid":           func(_, p map[string]any) { p["sid"] = nil },
		"empty sid":          func(_, p map[string]any) { p["sid"] = "" },
		"numeric sid":        func(_, p map[string]any) { p["sid"] = 7 },
		"no jti":             func(_, p map[string]any) { delete(p, "jti") },
		"no iat":             func(_, p map[string]any) { delete(p, "iat") },
		"null iat":           func(_, p map[string]any) { p["iat"] = nil },
		"string iat":         func(_, p map[string]any) { p["iat"] = "1795526400" },
		"fractional iat":     func(_, p map[string]any) { p["iat"] = 1795526400.5 },
		"htu with a query":   func(_, p map[string]any) { p["htu"] = "https://relay.example.com/wmp?x=1" },
		"htu with fragment":  func(_, p map[string]any) { p["htu"] = "https://relay.example.com/wmp#x" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, elliptic.P256())
			if _, err := f.verifier.Verify(f.resign(t, edit), f.want); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
	// The harness itself makes proofs that pass when nothing is edited.
	f := newFixture(t, elliptic.P256())
	if _, err := f.verifier.Verify(f.resign(t, func(_, _ map[string]any) {}), f.want); err != nil {
		t.Fatalf("unedited: %v", err)
	}
}

func TestVerifyRefusesTamperingAndGarbage(t *testing.T) {
	f := newFixture(t, elliptic.P256())
	parts := strings.Split(f.proof(t), ".")
	other := newFixture(t, elliptic.P256())
	other.req.SessionID = "ses-other"
	swapped := strings.Split(other.proof(t), ".")
	bad := []string{
		"", "a.b", "a.b.c.d", parts[0] + "." + parts[1] + ".",
		parts[0] + "." + swapped[1] + "." + parts[2], // another payload under this signature
		parts[0] + "." + parts[1] + "." + swapped[2], // another key's signature
		parts[0] + "=." + parts[1] + "." + parts[2],
		b64.EncodeToString([]byte(`{"alg":"ES256","alg":"none","typ":"wmp-proof+jwt"}`)) + "." + parts[1] + "." + parts[2],
	}
	for _, compact := range bad {
		if _, err := f.verifier.Verify(compact, f.want); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: got %v", compact, err)
		}
	}
}

func TestCreatorRefusesIncompleteInput(t *testing.T) {
	f := newFixture(t, elliptic.P256())
	for name, mutate := range map[string]func(){
		"no session":    func() { f.req.SessionID = "" },
		"no method":     func() { f.req.Method = "" },
		"relative url":  func() { f.req.URL = "/wmp" },
		"chain and kid": func() { f.creator.KeyID = "k" },
		"no signer":     func() { f.creator.Signer = nil },
	} {
		g := *f
		c := *f.creator
		f.creator = &c
		mutate()
		if _, err := f.creator.Proof(f.req); err == nil {
			t.Errorf("%s: no error", name)
		}
		*f = g
	}
	f.creator.Chain = nil
	if _, err := f.creator.Proof(f.req); err == nil {
		t.Error("neither chain nor kid: no error")
	}
}

func TestAuthorizeAndVerifyRequest(t *testing.T) {
	f := newFixture(t, elliptic.P256())
	r, _ := http.NewRequest(http.MethodGet, "http://relay.example.com/wmp/events?session_id=s1", nil)
	if err := f.creator.Authorize(r, "s1"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "DPoP ") {
		t.Fatalf("header %q", r.Header.Get("Authorization"))
	}
	r.Host = "relay.example.com"
	if p, err := f.verifier.VerifyRequest(r, "", "s1"); err != nil || p.SessionID != "s1" {
		t.Fatalf("%v", err)
	}
	if _, err := f.verifier.VerifyRequest(r, "https://relay.example.com/wmp/events", "s1"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("scheme mismatch: %v", err)
	}
	r.Header.Set("Authorization", "Bearer x")
	if _, err := f.verifier.VerifyRequest(r, "", "s1"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bearer: %v", err)
	}
}

func TestFromHeader(t *testing.T) {
	for in, want := range map[string]string{"DPoP a.b.c": "a.b.c", "dpop  a.b.c ": "a.b.c", "Bearer a.b.c": "", "DPoP": "", "DPoP ": "", "": ""} {
		got, ok := FromHeader(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
}

func TestNewSignerRefusesUnsupportedKeys(t *testing.T) {
	if _, err := NewSigner(nil); err == nil {
		t.Error("nil key")
	}
	k, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if _, err := NewSigner(k); err == nil {
		t.Error("P-224")
	}
}

// A proof made by wmp-js (createRequestProof with a WebCrypto P-256 key) for
// POST https://relay.example.com/wmp on ses-a1b2c3d4 at the test epoch.
const (
	jsProof    = "eyJhbGciOiJFUzI1NiIsInR5cCI6IndtcC1wcm9vZitqd3QiLCJraWQiOiJkaWQ6d2ViOndhbGxldC5leGFtcGxlLmNvbSNrZXktMSJ9.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9yZWxheS5leGFtcGxlLmNvbS93bXAiLCJpYXQiOjE3OTU1MjY0MDAsImp0aSI6IkcwOUlwMGpoRTc3Q0tnejN2RGtyLWciLCJzaWQiOiJzZXMtYTFiMmMzZDQifQ.VWR_E32_FK7VPT-o-uLYfyZS2bw4Eg9fAoZIw7YXlcwd4nx9dLbNawGQ4tniySSHkCdwmV-DrYupVwzYhv7G6Q"
	jsProofKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEG1sdU+APiZLqRXX/OamSDjZ/xGGmFYhYktUimRPLgQSoVde4sbb5E3CLKn8jOGflikb4ecjile7K345nAo31sA==" // base64 SubjectPublicKeyInfo
)

func TestVerifiesAProofMadeByWmpJS(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(jsProofKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{Now: fixedNow, ResolveKey: func(string) (crypto.PublicKey, error) { return pub, nil }}
	want := Expect{Method: "POST", URL: "https://relay.example.com/wmp", SessionID: "ses-a1b2c3d4"}
	p, err := v.Verify(jsProof, want)
	if err != nil {
		t.Fatal(err)
	}
	if p.KeyID != "did:web:wallet.example.com#key-1" || p.IssuedAt != epoch.Unix() {
		t.Fatalf("proof %+v", p)
	}
	want.SessionID = "ses-other"
	if _, err := v.Verify(jsProof, want); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another session: %v", err)
	}
}
