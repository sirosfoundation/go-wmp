package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp/proof"
)

const content = `{"to":["x509:san:dns:bob.example.com"],"content_type":"application/json","body":{"n":1}}`

type fixture struct {
	roots  *x509.CertPool
	chain  []*x509.Certificate
	key    *ecdsa.PrivateKey
	signer proof.Signer
}

func newFixture(t *testing.T, curve elliptic.Curve) *fixture {
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
	key, _ := ecdsa.GenerateKey(curve, rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "sender"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
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
	return &fixture{roots: pool, chain: []*x509.Certificate{leaf, ca}, key: key, signer: signer}
}

func decodeHeader(t *testing.T, sig string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(sig, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestSignShape(t *testing.T) {
	f := newFixture(t, elliptic.P256())
	sig, err := Sign([]byte(content), f.signer, Options{Chain: f.chain})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(sig, ".")
	if len(parts) != 3 || parts[1] != "" {
		t.Fatalf("not a detached JWS: %s", sig)
	}
	h := decodeHeader(t, sig)
	if h["alg"] != "ES256" || h["b64"] != false || len(h["crit"].([]any)) != 1 || h["crit"].([]any)[0] != "b64" {
		t.Fatalf("header %v", h)
	}
	if x5c := h["x5c"].([]any); len(x5c) != 2 || x5c[0] != base64.StdEncoding.EncodeToString(f.chain[0].Raw) {
		t.Fatalf("x5c %v", h["x5c"])
	}
	if _, ok := h["kid"]; ok {
		t.Fatal("kid without a KeyID")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if len(raw) != 64 {
		t.Fatalf("signature is %d bytes, want the 64 of R||S", len(raw))
	}
	// The signing input is ASCII(header) || "." || JCS(content), unencoded.
	canonical := `{"body":{"n":1},"content_type":"application/json","to":["x509:san:dns:bob.example.com"]}`
	digest := sha256.Sum256([]byte(parts[0] + "." + canonical))
	if !ecdsa.Verify(&f.key.PublicKey, digest[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
		t.Fatal("the signature does not cover header.JCS(content)")
	}
}

func TestRoundTrip(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		f := newFixture(t, curve)
		sig, err := Sign([]byte(content), f.signer, Options{Chain: f.chain, KeyID: "key-1"})
		if err != nil {
			t.Fatal(err)
		}
		v := &Verifier{Roots: f.roots}
		// The same object with another member order and spacing.
		reordered := `{ "body": {"n": 1}, "to": ["x509:san:dns:bob.example.com"], "content_type": "application/json" }`
		got, err := v.Verify(sig, []byte(reordered))
		if err != nil {
			t.Fatalf("%s: %v", curve.Params().Name, err)
		}
		if got.KeyID != "key-1" || len(got.Chain) != 2 || !got.Chain[0].Equal(f.chain[0]) {
			t.Fatalf("%s: got %+v", curve.Params().Name, got)
		}
	}
}

func TestRoundTripKid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := proof.NewSigner(priv)
	sig, err := Sign([]byte(content), signer, Options{KeyID: "did:web:alice.example.com#key-1"})
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(kid string) (crypto.PublicKey, error) {
		if kid == "did:web:alice.example.com#key-1" {
			return pub, nil
		}
		return nil, errors.New("unknown")
	}
	got, err := (&Verifier{ResolveKey: resolve}).Verify(sig, []byte(content))
	if err != nil || got.Algorithm != proof.AlgEdDSA {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := (&Verifier{}).Verify(sig, []byte(content)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("without ResolveKey: %v", err)
	}
	other := func(string) (crypto.PublicKey, error) { return nil, errors.New("unknown") }
	if _, err := (&Verifier{ResolveKey: other}).Verify(sig, []byte(content)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("with an unresolved kid: %v", err)
	}
}

func TestSignRequiresAKeyReference(t *testing.T) {
	f := newFixture(t, elliptic.P256())
	if _, err := Sign([]byte(content), f.signer, Options{}); err == nil {
		t.Fatal("signed without Chain and KeyID")
	}
	if _, err := Sign([]byte(`{"a":1,"a":2}`), f.signer, Options{KeyID: "k"}); err == nil {
		t.Fatal("signed content with a duplicate member")
	}
}

func TestVerifyRefuses(t *testing.T) {
	f := newFixture(t, elliptic.P256())
	sig, err := Sign([]byte(content), f.signer, Options{Chain: f.chain})
	if err != nil {
		t.Fatal(err)
	}
	other := newFixture(t, elliptic.P256())
	cases := map[string]struct {
		v       *Verifier
		sig     string
		content string
	}{
		"changed content":           {&Verifier{Roots: f.roots}, sig, strings.Replace(content, `"n":1`, `"n":2`, 1)},
		"no trust anchors":          {&Verifier{}, sig, content},
		"other trust anchors":       {&Verifier{Roots: other.roots}, sig, content},
		"an expired chain":          {&Verifier{Roots: f.roots, Now: func() time.Time { return time.Now().Add(48 * time.Hour) }}, sig, content},
		"an algorithm not accepted": {&Verifier{Roots: f.roots, Algorithms: []string{proof.AlgEdDSA}}, sig, content},
		"an attached payload":       {&Verifier{Roots: f.roots}, strings.Replace(sig, "..", ".e30.", 1), content},
		"two segments":              {&Verifier{Roots: f.roots}, strings.Replace(sig, "..", ".", 1), content},
		"an empty signature":        {&Verifier{Roots: f.roots}, sig[:strings.Index(sig, "..")+2], content},
		"padding":                   {&Verifier{Roots: f.roots}, sig + "=", content},
		"content with a duplicate":  {&Verifier{Roots: f.roots}, sig, `{"body":1,"body":1}`},
		"content that is not JSON":  {&Verifier{Roots: f.roots}, sig, `nope`},
	}
	for name, c := range cases {
		if _, err := c.v.Verify(c.sig, []byte(c.content)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
	if _, err := (&Verifier{Roots: f.roots}).Verify(sig, []byte(content)); err != nil {
		t.Fatalf("the unmodified signature: %v", err)
	}
	// Without Roots a chain is refused outright: the system roots are never
	// the trust anchors of a content signature.
	if _, err := (&Verifier{}).Verify(sig, []byte(content)); err == nil || !strings.Contains(err.Error(), "x5c signatures are not accepted") {
		t.Fatalf("no trust anchors: %v", err)
	}
}

// resign signs content under an edited header, so that only the header rule
// under test can refuse the result.
func (f *fixture) resign(t *testing.T, edit func(h map[string]any)) string {
	t.Helper()
	h := map[string]any{
		"alg": "ES256", "b64": false, "crit": []string{"b64"},
		"x5c": []string{base64.StdEncoding.EncodeToString(f.chain[0].Raw), base64.StdEncoding.EncodeToString(f.chain[1].Raw)},
	}
	edit(h)
	raw, _ := json.Marshal(h)
	protected := base64.RawURLEncoding.EncodeToString(raw)
	canonical := `{"body":{"n":1},"content_type":"application/json","to":["x509:san:dns:bob.example.com"]}`
	sig, err := f.signer.Sign([]byte(protected + "." + canonical))
	if err != nil {
		t.Fatal(err)
	}
	return protected + ".." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyRefusesHeaders(t *testing.T) {
	f := newFixture(t, elliptic.P256())
	resolve := func(string) (crypto.PublicKey, error) { return &f.key.PublicKey, nil }
	v := &Verifier{Roots: f.roots, ResolveKey: resolve}
	if _, err := v.Verify(f.resign(t, func(map[string]any) {}), []byte(content)); err != nil {
		t.Fatalf("the unedited header: %v", err)
	}
	cases := map[string]func(h map[string]any){
		"b64 true":                      func(h map[string]any) { h["b64"] = true },
		"b64 absent":                    func(h map[string]any) { delete(h, "b64") },
		"b64 null":                      func(h map[string]any) { h["b64"] = nil },
		"crit absent":                   func(h map[string]any) { delete(h, "crit") },
		"crit null":                     func(h map[string]any) { h["crit"] = nil },
		"an unknown critical parameter": func(h map[string]any) { h["crit"] = []string{"b64", "exp"} },
		"alg none":                      func(h map[string]any) { h["alg"] = "none" },
		"alg null":                      func(h map[string]any) { h["alg"] = nil },
		"alg of another key type":       func(h map[string]any) { h["alg"] = "EdDSA" },
		"x5c null":                      func(h map[string]any) { h["x5c"] = nil },
		"an empty x5c":                  func(h map[string]any) { h["x5c"] = []string{} },
		"an x5c entry that is no cert":  func(h map[string]any) { h["x5c"] = []string{"AAAA"} },
		"kid null":                      func(h map[string]any) { h["kid"] = nil },
		"an empty kid":                  func(h map[string]any) { h["kid"] = "" },
	}
	for name, edit := range cases {
		if _, err := v.Verify(f.resign(t, edit), []byte(content)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
	// Without x5c the key comes from kid; without either there is none.
	if _, err := v.Verify(f.resign(t, func(h map[string]any) { delete(h, "x5c") }), []byte(content)); !errors.Is(err, ErrInvalid) {
		t.Errorf("no key reference: got %v", err)
	}
	if _, err := v.Verify(f.resign(t, func(h map[string]any) { delete(h, "x5c"); h["kid"] = "k" }), []byte(content)); err != nil {
		t.Errorf("kid only: %v", err)
	}
}

type derSigner struct{ key *ecdsa.PrivateKey }

func (derSigner) Algorithm() string { return proof.AlgES256 }
func (s derSigner) Sign(input []byte) ([]byte, error) {
	digest := sha256.Sum256(input)
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, ss})
}

func TestVerifyRefusesADEREncodedSignature(t *testing.T) {
	f := newFixture(t, elliptic.P256())
	sig, err := Sign([]byte(content), derSigner{f.key}, Options{Chain: f.chain})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Verifier{Roots: f.roots}).Verify(sig, []byte(content)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestContentObject(t *testing.T) {
	got, err := ContentObject([]byte(`{"wmp":{"version":"0.1","signature":"x"},"ciphertext":"abc","plaintext_hash":{"algorithm":"sha-256","value":"v"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"ciphertext":"abc","plaintext_hash":{"algorithm":"sha-256","value":"v"}}`; string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	for _, bad := range []string{`[]`, `{"a":1,"a":2}`, `{"a":1}x`, `null`} {
		if _, err := ContentObject([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

// A signature made by wmp-js (signContent) with an Ed25519 key named by kid.
func TestVerifiesASignatureMadeByWmpJS(t *testing.T) {
	const sig = "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il0sImtpZCI6ImRpZDp3ZWI6c2VuZGVyLmV4YW1wbGUuY29tI2tleS0xIn0..YuUXJ8KJqSA-ixjgU5WmOq-Y8eYN1mT_TonbnoS0TQmYlYe-5BPMQOTeGAeHaTNAFcPS7A6TdQMm0xmAcMV1DQ"
	const spki = "MCowBQYDK2VwAyEAPZH4yJaZ2Enc3QSA8Hq+ZPyYgE5LX5R+9BQblIlao8k="
	const vector = `{"ciphertext":"AAECAwQ","plaintext_hash":{"algorithm":"sha-256","value":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"}}`
	der, _ := base64.StdEncoding.DecodeString(spki)
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{ResolveKey: func(kid string) (crypto.PublicKey, error) {
		if kid != "did:web:sender.example.com#key-1" {
			return nil, errors.New("unknown")
		}
		return pub, nil
	}}
	got, err := v.Verify(sig, []byte(vector))
	if err != nil || got.Algorithm != proof.AlgEdDSA || got.KeyID != "did:web:sender.example.com#key-1" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := v.Verify(sig, []byte(strings.Replace(vector, "AAECAwQ", "AAECAwU", 1))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("changed content: %v", err)
	}
}
