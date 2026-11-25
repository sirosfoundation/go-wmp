// Package proof implements the per-request proof for HTTPS sessions of WMP
// Core section 4.4.8: a compact JWS, modelled on DPoP (RFC 9449), that binds
// one HTTP request to one WMP session and proves possession of the key the
// session was authenticated with.
//
// A client makes proofs with a Creator and sends each one as
// "Authorization: DPoP <proof>". A server checks them with a Verifier.
package proof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// Type is the "typ" header parameter of a proof.
	Type = "wmp-proof+jwt"
	// Scheme is the Authorization scheme a proof is sent under.
	Scheme = "DPoP"
	// DefaultSkew is the default clock-skew tolerance (WMP Core section 8.5.1).
	DefaultSkew = 30 * time.Second
)

// JWS algorithms of a proof.
const (
	AlgES256 = "ES256"
	AlgES384 = "ES384"
	AlgES512 = "ES512"
	AlgEdDSA = "EdDSA"
)

var b64 = base64.RawURLEncoding.Strict()

// Claims is the payload of a proof.
type Claims struct {
	// Method is "htm": the HTTP request method.
	Method string
	// URL is "htu": the HTTP request URI without query and fragment.
	URL string
	// IssuedAt is "iat" in unix seconds.
	IssuedAt int64
	// ID is "jti": the unique identifier of this proof.
	ID string
	// SessionID is "sid": the WMP session the proof is bound to. Empty for
	// the proof of a wmp.session.create, which carries no "sid".
	SessionID string
	// TokenHash is "ath": the base64url SHA-256 of the access token the
	// request also carries (RFC 9449 section 4.2). Empty when there is none.
	TokenHash string
}

// canonical returns the JCS (RFC 8785) serialisation of the claims.
func (c Claims) canonical() ([]byte, error) {
	var b []byte
	b = append(b, '{')
	if c.TokenHash != "" {
		b = appendMember(b, "ath", c.TokenHash)
		b = append(b, ',')
	}
	b = appendMember(b, "htm", c.Method)
	b = append(b, ',')
	b = appendMember(b, "htu", c.URL)
	b = append(b, `,"iat":`...)
	b = strconv.AppendInt(b, c.IssuedAt, 10)
	b = append(b, ',')
	b = appendMember(b, "jti", c.ID)
	if c.SessionID != "" {
		b = append(b, ',')
		b = appendMember(b, "sid", c.SessionID)
	}
	b = append(b, '}')
	for _, s := range []string{c.TokenHash, c.Method, c.URL, c.ID, c.SessionID} {
		if !utf8.ValidString(s) {
			return nil, errors.New("proof: claim is not valid UTF-8")
		}
	}
	return b, nil
}

func appendMember(b []byte, name, value string) []byte {
	b = append(b, '"')
	b = append(b, name...)
	b = append(b, '"', ':')
	return appendJCSString(b, value)
}

// appendJCSString appends s as a JSON string in the RFC 8785 form: only the
// quote, the backslash and the C0 controls are escaped.
func appendJCSString(b []byte, s string) []byte {
	const hexDigits = "0123456789abcdef"
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b = append(b, '\\', c)
		case c == '\b':
			b = append(b, '\\', 'b')
		case c == '\t':
			b = append(b, '\\', 't')
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\f':
			b = append(b, '\\', 'f')
		case c == '\r':
			b = append(b, '\\', 'r')
		case c < 0x20:
			b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		default:
			b = append(b, c)
		}
	}
	return append(b, '"')
}

// Signer signs the JWS signing input of a proof.
type Signer interface {
	// Algorithm is the JWS "alg" of the signatures Sign makes.
	Algorithm() string
	// Sign returns the JWS signature over input (for ECDSA the fixed-width
	// R||S form of RFC 7518 section 3.4).
	Sign(input []byte) ([]byte, error)
}

type keySigner struct {
	alg string
	key crypto.Signer
}

// NewSigner returns a Signer for an ECDSA (P-256, P-384, P-521) or Ed25519
// key. The key may live in hardware: only crypto.Signer is used.
func NewSigner(key crypto.Signer) (Signer, error) {
	if key == nil {
		return nil, errors.New("proof: nil key")
	}
	alg, err := algorithmFor(key.Public())
	if err != nil {
		return nil, err
	}
	return keySigner{alg: alg, key: key}, nil
}

func (s keySigner) Algorithm() string { return s.alg }

func (s keySigner) Sign(input []byte) ([]byte, error) {
	if s.alg == AlgEdDSA {
		return s.key.Sign(rand.Reader, input, crypto.Hash(0))
	}
	h, size := ecParams(s.alg)
	hh := h.New()
	hh.Write(input)
	der, err := s.key.Sign(rand.Reader, hh.Sum(nil), h)
	if err != nil {
		return nil, err
	}
	return derToRaw(der, size)
}

func algorithmFor(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return AlgES256, nil
		case elliptic.P384():
			return AlgES384, nil
		case elliptic.P521():
			return AlgES512, nil
		}
		return "", errors.New("proof: unsupported curve")
	case ed25519.PublicKey:
		return AlgEdDSA, nil
	}
	return "", fmt.Errorf("proof: unsupported key type %T", pub)
}

// ecParams returns the hash and the coordinate size of an ECDSA algorithm.
func ecParams(alg string) (crypto.Hash, int) {
	switch alg {
	case AlgES384:
		return crypto.SHA384, 48
	case AlgES512:
		return crypto.SHA512, 66
	}
	return crypto.SHA256, 32
}

func newHash(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	}
	return sha256.New()
}

// Creator makes proofs for one key.
type Creator struct {
	// Signer signs the proofs. Required.
	Signer Signer
	// Chain is the certificate chain of the key, leaf first, placed in the
	// "x5c" header. Set it for sessions authenticated with x5c.
	Chain []*x509.Certificate
	// KeyID is the DID Document key id placed in the "kid" header. Set it,
	// instead of Chain, for sessions authenticated with signed_challenge.
	KeyID string
	// Now returns the current time. Default time.Now.
	Now func() time.Time
}

// Request names the HTTP request a proof is made for.
type Request struct {
	// Method is the HTTP method.
	Method string
	// URL is the request URL. Its query and fragment are left out of "htu".
	URL string
	// SessionID is the WMP session of the request. It is empty only for a
	// wmp.session.create, whose proof carries no "sid".
	SessionID string
	// AccessToken is the bearer token the request also carries (the dpop
	// auth type); its hash becomes "ath". Empty when there is none.
	AccessToken string
}

// Proof returns a compact JWS proof for req.
func (c *Creator) Proof(req Request) (string, error) {
	if c.Signer == nil {
		return "", errors.New("proof: no signer")
	}
	if (len(c.Chain) == 0) == (c.KeyID == "") {
		return "", errors.New("proof: exactly one of Chain and KeyID is required")
	}
	if req.Method == "" {
		return "", errors.New("proof: method is required")
	}
	htu, err := normalizeURL(req.URL, true)
	if err != nil {
		return "", err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	claims := Claims{
		Method:    req.Method,
		URL:       htu,
		IssuedAt:  now().Unix(),
		ID:        hex.EncodeToString(id),
		SessionID: req.SessionID,
		TokenHash: tokenHash(req.AccessToken),
	}
	payload, err := claims.canonical()
	if err != nil {
		return "", err
	}

	header := map[string]any{"alg": c.Signer.Algorithm(), "typ": Type}
	if c.KeyID != "" {
		header["kid"] = c.KeyID
	} else {
		x5c := make([]string, len(c.Chain))
		for i, cert := range c.Chain {
			x5c[i] = base64.StdEncoding.EncodeToString(cert.Raw)
		}
		header["x5c"] = x5c
	}
	hdr, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(hdr) + "." + b64.EncodeToString(payload)
	sig, err := c.Signer.Sign([]byte(input))
	if err != nil {
		return "", fmt.Errorf("proof: sign: %w", err)
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// Authorize sets the Authorization header of r to a proof for it on the
// session sessionID. sessionID is empty only for a wmp.session.create.
func (c *Creator) Authorize(r *http.Request, sessionID string) error {
	p, err := c.Proof(Request{Method: r.Method, URL: r.URL.String(), SessionID: sessionID})
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", Scheme+" "+p)
	return nil
}

func tokenHash(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return b64.EncodeToString(sum[:])
}

func derToRaw(der []byte, size int) ([]byte, error) {
	r, s, err := parseECDSASignature(der)
	if err != nil {
		return nil, err
	}
	if r.BitLen() > size*8 || s.BitLen() > size*8 {
		return nil, errors.New("proof: signature out of range")
	}
	out := make([]byte, 2*size)
	r.FillBytes(out[:size])
	s.FillBytes(out[size:])
	return out, nil
}

// FromHeader returns the proof in an Authorization header value. ok is false
// when the value does not use the DPoP scheme.
func FromHeader(authorization string) (proof string, ok bool) {
	scheme, rest, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, Scheme) {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	return rest, rest != ""
}

func bigFromBytes(b []byte) *big.Int { return new(big.Int).SetBytes(b) }
