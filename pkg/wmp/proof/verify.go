package proof

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrInvalid is wrapped by every error Verify returns for a proof that does
// not pass. A server answers such a request with 401.
var ErrInvalid = errors.New("proof: invalid proof")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Proof is a verified proof.
type Proof struct {
	Claims
	// Algorithm is the JWS "alg".
	Algorithm string
	// Chain is the verified "x5c" certificate chain, leaf first. Nil for a
	// "kid" proof.
	Chain []*x509.Certificate
	// KeyID is the "kid" header. Empty for an "x5c" proof.
	KeyID string
	// Key is the public key that verified the signature.
	Key crypto.PublicKey
}

// ReplayCache remembers proof identifiers for as long as a proof stays
// inside the clock-skew window.
type ReplayCache interface {
	// Seen records key until expires and reports whether it was already
	// recorded and has not expired.
	Seen(key string, expires time.Time) bool
}

// Verifier checks proofs. The zero value refuses every proof: set Roots to
// accept "x5c" proofs and ResolveKey to accept "kid" proofs.
type Verifier struct {
	// Roots are the trust anchors of "x5c" chains. A proof with a chain is
	// refused when Roots is nil.
	Roots *x509.CertPool
	// KeyUsages are the extended key usages a leaf certificate must allow.
	// Default: any.
	KeyUsages []x509.ExtKeyUsage
	// ResolveKey returns the public key of a "kid" (a DID Document key id).
	// A proof with a kid is refused when ResolveKey is nil.
	ResolveKey func(kid string) (crypto.PublicKey, error)
	// Algorithms are the accepted JWS algorithms. Default: ES256, ES384,
	// ES512 and EdDSA.
	Algorithms []string
	// Skew is the clock-skew tolerance on "iat". Default DefaultSkew.
	Skew time.Duration
	// Replay detects a proof presented twice. Nil disables the check.
	Replay ReplayCache
	// Now returns the current time. Default time.Now.
	Now func() time.Time
}

// Expect is what a proof must be bound to.
type Expect struct {
	// Method is the method of the request the proof arrived on.
	Method string
	// URL is the URL the request was sent to, as the client saw it.
	URL string
	// SessionID is the session the request names. When it is empty the
	// "sid" claim is not compared and the caller MUST compare the returned
	// Proof.SessionID itself.
	SessionID string
	// AccessToken is the bearer token the request also carries. When set,
	// the proof must carry its hash in "ath"; when empty, a proof with an
	// "ath" is refused.
	AccessToken string
}

// Verify checks the compact JWS proof against want (WMP Core section 4.4.8,
// verification steps 1 to 5). The caller still matches the returned identity
// (the leaf certificate's SAN, or the key id) to the principal the session
// was created under.
func (v *Verifier) Verify(compact string, want Expect) (*Proof, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, invalid("not a three-segment compact JWS")
	}
	rawHeader, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, invalid("header encoding")
	}
	rawPayload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, invalid("payload encoding")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, invalid("signature encoding")
	}

	p, err := v.parseHeader(rawHeader)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(p.Algorithm, p.Key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, err
	}
	if p.Claims, err = parseClaims(rawPayload); err != nil {
		return nil, err
	}

	if want.SessionID != "" && subtle.ConstantTimeCompare([]byte(p.SessionID), []byte(want.SessionID)) != 1 {
		return nil, invalid("sid does not name this session")
	}
	if p.Method != want.Method {
		return nil, invalid("htm does not match the request")
	}
	wantURL, err := normalizeURL(want.URL, true)
	if err != nil {
		return nil, invalid("request URL: %v", err)
	}
	gotURL, err := normalizeURL(p.URL, false)
	if err != nil || gotURL != wantURL {
		return nil, invalid("htu does not match the request")
	}
	if p.TokenHash != tokenHash(want.AccessToken) {
		return nil, invalid("ath does not match the access token")
	}

	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	skew := v.Skew
	if skew <= 0 {
		skew = DefaultSkew
	}
	issued := time.Unix(p.IssuedAt, 0)
	if issued.Before(now.Add(-skew)) || issued.After(now.Add(skew)) {
		return nil, invalid("iat outside the clock-skew tolerance")
	}
	if len(p.Chain) > 0 {
		if err := v.verifyChain(p.Chain, now); err != nil {
			return nil, err
		}
	}
	// Last, so that only an otherwise valid proof consumes its jti.
	if v.Replay != nil && v.Replay.Seen(p.SessionID+"\x00"+p.ID, issued.Add(2*skew)) {
		return nil, invalid("jti was already used")
	}
	return p, nil
}

// VerifyRequest checks the proof in the Authorization header of r. url is
// the URL the client sent the request to; when it is empty it is taken from
// r (see RequestURL), which is only right when no proxy rewrites the request.
func (v *Verifier) VerifyRequest(r *http.Request, url, sessionID string) (*Proof, error) {
	compact, ok := FromHeader(r.Header.Get("Authorization"))
	if !ok {
		return nil, invalid("no proof in the Authorization header")
	}
	if url == "" {
		url = RequestURL(r)
	}
	return v.Verify(compact, Expect{Method: r.Method, URL: url, SessionID: sessionID})
}

// RequestURL returns the URL of a server request as seen by this process:
// https when the connection is TLS, the Host header and the path.
func RequestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.EscapedPath()
}

func (v *Verifier) allows(alg string) bool {
	algs := v.Algorithms
	if algs == nil {
		algs = []string{AlgES256, AlgES384, AlgES512, AlgEdDSA}
	}
	for _, a := range algs {
		if a == alg {
			return true
		}
	}
	return false
}

// parseHeader checks the protected header and returns the proof with its
// key material filled in.
func (v *Verifier) parseHeader(raw []byte) (*Proof, error) {
	members, err := object(raw)
	if err != nil {
		return nil, invalid("header is not a JSON object")
	}
	alg, err := stringMember(members, "alg")
	if err != nil {
		return nil, err
	}
	typ, err := stringMember(members, "typ")
	if err != nil {
		return nil, err
	}
	if typ != Type {
		return nil, invalid("typ is not %s", Type)
	}
	if !v.allows(alg) {
		return nil, invalid("algorithm %q is not accepted", alg)
	}
	if _, ok := members["crit"]; ok {
		return nil, invalid("crit is not supported")
	}
	p := &Proof{Algorithm: alg}
	_, hasChain := members["x5c"]
	_, hasKid := members["kid"]
	switch {
	case hasChain == hasKid:
		return nil, invalid("exactly one of x5c and kid is required")
	case hasChain:
		if p.Chain, err = parseChain(members["x5c"]); err != nil {
			return nil, err
		}
		if v.Roots == nil {
			return nil, invalid("x5c proofs are not accepted")
		}
		p.Key = p.Chain[0].PublicKey
	default:
		if p.KeyID, err = stringMember(members, "kid"); err != nil {
			return nil, err
		}
		if v.ResolveKey == nil {
			return nil, invalid("kid proofs are not accepted")
		}
		if p.Key, err = v.ResolveKey(p.KeyID); err != nil || p.Key == nil {
			return nil, invalid("kid does not resolve")
		}
	}
	return p, nil
}

func parseChain(raw json.RawMessage) ([]*x509.Certificate, error) {
	var entries []json.RawMessage
	if isNull(raw) || json.Unmarshal(raw, &entries) != nil || len(entries) == 0 {
		return nil, invalid("x5c is not a non-empty array")
	}
	chain := make([]*x509.Certificate, len(entries))
	for i, e := range entries {
		var s string
		if isNull(e) || json.Unmarshal(e, &s) != nil {
			return nil, invalid("x5c entry is not a string")
		}
		der, err := base64.StdEncoding.Strict().DecodeString(s)
		if err != nil {
			return nil, invalid("x5c entry encoding")
		}
		if chain[i], err = x509.ParseCertificate(der); err != nil {
			return nil, invalid("x5c entry is not a certificate")
		}
	}
	return chain, nil
}

func (v *Verifier) verifyChain(chain []*x509.Certificate, now time.Time) error {
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	usages := v.KeyUsages
	if usages == nil {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots: v.Roots, Intermediates: inter, CurrentTime: now, KeyUsages: usages,
	}); err != nil {
		return invalid("certificate chain: %v", err)
	}
	return nil
}

func parseClaims(raw []byte) (Claims, error) {
	var c Claims
	members, err := object(raw)
	if err != nil {
		return c, invalid("payload is not a JSON object")
	}
	if c.Method, err = stringMember(members, "htm"); err != nil {
		return c, err
	}
	if c.URL, err = stringMember(members, "htu"); err != nil {
		return c, err
	}
	if c.ID, err = stringMember(members, "jti"); err != nil {
		return c, err
	}
	if c.SessionID, err = stringMember(members, "sid"); err != nil {
		return c, err
	}
	if _, ok := members["ath"]; ok {
		if c.TokenHash, err = stringMember(members, "ath"); err != nil {
			return c, err
		}
	}
	iat, ok := members["iat"]
	if !ok {
		return c, invalid("iat is missing")
	}
	dec := json.NewDecoder(bytes.NewReader(iat))
	dec.UseNumber()
	var n json.Number
	// A quoted number decodes into a json.Number too: refuse it by its first byte.
	if trimmed := bytes.TrimSpace(iat); isNull(iat) || len(trimmed) == 0 || trimmed[0] == '"' || dec.Decode(&n) != nil {
		return c, invalid("iat is not a number")
	}
	if c.IssuedAt, err = n.Int64(); err != nil {
		return c, invalid("iat is not an integer")
	}
	return c, nil
}

// object decodes a JSON object, refusing a member name that appears twice.
func object(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, _ := tok.(string)
		if _, dup := out[name]; dup {
			return nil, errors.New("duplicate member")
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[name] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	return out, nil
}

func isNull(raw json.RawMessage) bool { return string(bytes.TrimSpace(raw)) == "null" }

// stringMember returns a required, non-empty string member.
func stringMember(members map[string]json.RawMessage, name string) (string, error) {
	raw, ok := members[name]
	var s string
	if !ok || isNull(raw) || json.Unmarshal(raw, &s) != nil || s == "" {
		return "", invalid("%s is not a non-empty string", name)
	}
	return s, nil
}

func verifySignature(alg string, key crypto.PublicKey, input, sig []byte) error {
	want, err := algorithmFor(key)
	if err != nil || want != alg {
		return invalid("key does not fit algorithm %s", alg)
	}
	switch k := key.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, input, sig) {
			return invalid("signature")
		}
	case *ecdsa.PublicKey:
		h, size := ecParams(alg)
		if len(sig) != 2*size {
			return invalid("signature length")
		}
		hh := newHash(h)
		hh.Write(input)
		if !ecdsa.Verify(k, hh.Sum(nil), bigFromBytes(sig[:size]), bigFromBytes(sig[size:])) {
			return invalid("signature")
		}
	}
	return nil
}

func parseECDSASignature(der []byte) (r, s *big.Int, err error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, nil, errors.New("proof: malformed ECDSA signature")
	}
	return sig.R, sig.S, nil
}

// normalizeURL returns the "htu" form of raw: scheme and host in lower case,
// the default port removed, an empty path as "/". With strip the query and
// fragment are dropped; without it a URL that carries either is refused.
func normalizeURL(raw string, strip bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("proof: malformed URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "https" && scheme != "http") || u.Host == "" || u.User != nil || u.Opaque != "" {
		return "", errors.New("proof: not an absolute http(s) URL")
	}
	if !strip && (u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#")) {
		return "", errors.New("proof: htu carries a query or fragment")
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && !(scheme == "https" && port == "443") && !(scheme == "http" && port == "80") {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

type memoryReplay struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

// NewMemoryReplayCache returns an in-process ReplayCache. A deployment with
// several instances needs a shared one.
func NewMemoryReplayCache() ReplayCache {
	return &memoryReplay{seen: map[string]time.Time{}, now: time.Now}
}

func (m *memoryReplay) Seen(key string, expires time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, exp := range m.seen {
		if !exp.After(now) {
			delete(m.seen, k)
		}
	}
	if _, ok := m.seen[key]; ok {
		return true
	}
	m.seen[key] = expires
	return false
}
