// Package signature implements the non-repudiation signature of WMP Core
// section 5.4: a detached JWS (RFC 7515 Appendix F) with an unencoded payload
// (RFC 7797) over the RFC 8785 form of a message's content object, made with
// the sender's long-lived key. Its value, carried in wmp.signature, is
// "<header>..<signature>"; an ECDSA signature is the fixed-width R||S form of
// JWS, not DER.
package signature

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp/jcs"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/proof"
)

// ErrInvalid is wrapped by every error of a signature that does not verify.
// A receiver answers the message with -31010.
var ErrInvalid = errors.New("signature: invalid content signature")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

var b64 = base64.RawURLEncoding.Strict()

// ContentObject returns the content object of a request (WMP Core section
// 5.4): its params without the "wmp" member. For an encrypted message that is
// {"ciphertext": ...}, plus "plaintext_hash" when the sender commits to the
// plaintext.
func ContentObject(params []byte) ([]byte, error) {
	members, err := object(params)
	if err != nil {
		return nil, fmt.Errorf("signature: params: %w", err)
	}
	delete(members, "wmp")
	return json.Marshal(members)
}

// Options name the signing key in the JWS header: by its certificate chain,
// by a key identifier, or by both.
type Options struct {
	// Chain is the certificate chain of the signing key, leaf first.
	Chain []*x509.Certificate
	// KeyID is the "kid": a DID URL, an X.509 subject key identifier or a JWK
	// thumbprint.
	KeyID string
}

// Sign signs a content object (a JSON text) and returns the wmp.signature
// value.
func Sign(content []byte, signer proof.Signer, opts Options) (string, error) {
	if signer == nil {
		return "", errors.New("signature: no signer")
	}
	if len(opts.Chain) == 0 && opts.KeyID == "" {
		return "", errors.New("signature: one of Chain and KeyID is required")
	}
	header := map[string]any{"alg": signer.Algorithm(), "b64": false, "crit": []string{"b64"}}
	if opts.KeyID != "" {
		header["kid"] = opts.KeyID
	}
	if len(opts.Chain) > 0 {
		x5c := make([]string, len(opts.Chain))
		for i, c := range opts.Chain {
			x5c[i] = base64.StdEncoding.EncodeToString(c.Raw)
		}
		header["x5c"] = x5c
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Canonicalize(content)
	if err != nil {
		return "", fmt.Errorf("signature: content: %w", err)
	}
	protected := b64.EncodeToString(headerJSON)
	sig, err := signer.Sign(signingInput(protected, canonical))
	if err != nil {
		return "", fmt.Errorf("signature: %w", err)
	}
	return protected + ".." + b64.EncodeToString(sig), nil
}

// signingInput is ASCII(header) || "." || M, the payload M unencoded.
func signingInput(protected string, canonical []byte) []byte {
	input := make([]byte, 0, len(protected)+1+len(canonical))
	input = append(input, protected...)
	input = append(input, '.')
	return append(input, canonical...)
}

// Signature is a verified content signature.
type Signature struct {
	// Algorithm is the JWS "alg".
	Algorithm string
	// Chain is the validated "x5c" chain, leaf first, when the header has one.
	Chain []*x509.Certificate
	// KeyID is the "kid" header, when present.
	KeyID string
	// Key is the public key that verified the signature.
	Key crypto.PublicKey
}

// Verifier checks content signatures. The zero value accepts none: a
// signature with a chain needs Roots, one named only by "kid" needs
// ResolveKey.
type Verifier struct {
	// Roots are the trust anchors of "x5c" chains.
	Roots *x509.CertPool
	// KeyUsages are the extended key usages a leaf must allow. Default: any.
	KeyUsages []x509.ExtKeyUsage
	// ResolveKey returns the public key of a "kid".
	ResolveKey func(kid string) (crypto.PublicKey, error)
	// Algorithms are the accepted JWS algorithms. Default: ES256, ES384,
	// ES512 and EdDSA.
	Algorithms []string
	// Now is the time certificates are validated at. Default: time.Now.
	Now func() time.Time
}

// Verify checks a wmp.signature value over a content object (a JSON text).
// The key is the leaf of the header's "x5c" chain when there is one,
// otherwise the key of its "kid". The caller still matches the returned
// identity to the sender.
func (v *Verifier) Verify(signature string, content []byte) (*Signature, error) {
	parts := strings.Split(signature, ".")
	if len(parts) != 3 || parts[1] != "" || parts[0] == "" || parts[2] == "" {
		return nil, invalid("not a detached compact JWS")
	}
	headerJSON, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, invalid("header encoding")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, invalid("signature encoding")
	}
	s, err := v.parseHeader(headerJSON)
	if err != nil {
		return nil, err
	}
	canonical, err := jcs.Canonicalize(content)
	if err != nil {
		return nil, invalid("the content has no canonical form")
	}
	if err := proof.VerifySignature(s.Algorithm, s.Key, signingInput(parts[0], canonical), sig); err != nil {
		return nil, invalid("%s", strings.TrimPrefix(err.Error(), proof.ErrInvalid.Error()+": "))
	}
	if len(s.Chain) > 0 {
		if err := v.verifyChain(s.Chain); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (v *Verifier) allows(alg string) bool {
	algs := v.Algorithms
	if algs == nil {
		algs = []string{proof.AlgES256, proof.AlgES384, proof.AlgES512, proof.AlgEdDSA}
	}
	for _, a := range algs {
		if a == alg {
			return true
		}
	}
	return false
}

func (v *Verifier) parseHeader(raw []byte) (*Signature, error) {
	header, err := object(raw)
	if err != nil {
		return nil, invalid("header: %v", err)
	}
	s := &Signature{}
	if json.Unmarshal(header["alg"], &s.Algorithm) != nil || isNull(header["alg"]) || !v.allows(s.Algorithm) {
		return nil, invalid("algorithm is not accepted")
	}
	if string(bytes.TrimSpace(header["b64"])) != "false" {
		return nil, invalid("b64 is not false")
	}
	// "b64" must be critical and is the only critical parameter understood here.
	var crit []json.RawMessage
	if isNull(header["crit"]) || json.Unmarshal(header["crit"], &crit) != nil || len(crit) != 1 || string(bytes.TrimSpace(crit[0])) != `"b64"` {
		return nil, invalid(`crit is not ["b64"]`)
	}
	if raw, ok := header["kid"]; ok {
		if isNull(raw) || json.Unmarshal(raw, &s.KeyID) != nil || s.KeyID == "" {
			return nil, invalid("kid is not a non-empty string")
		}
	}
	if raw, ok := header["x5c"]; ok {
		if s.Chain, err = parseChain(raw); err != nil {
			return nil, err
		}
		if v.Roots == nil {
			return nil, invalid("x5c signatures are not accepted")
		}
		s.Key = s.Chain[0].PublicKey
		return s, nil
	}
	if s.KeyID == "" {
		return nil, invalid("the header names no key")
	}
	if v.ResolveKey == nil {
		return nil, invalid("kid signatures are not accepted")
	}
	if s.Key, err = v.ResolveKey(s.KeyID); err != nil || s.Key == nil {
		return nil, invalid("kid does not resolve")
	}
	return s, nil
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

func (v *Verifier) verifyChain(chain []*x509.Certificate) error {
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	usages := v.KeyUsages
	if usages == nil {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots: v.Roots, Intermediates: inter, CurrentTime: now, KeyUsages: usages,
	}); err != nil {
		return invalid("certificate chain: %v", err)
	}
	return nil
}

func isNull(raw json.RawMessage) bool { return string(bytes.TrimSpace(raw)) == "null" }

// object decodes a JSON object, refusing duplicate members and trailing data.
func object(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	members := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errors.New("not a JSON object")
		}
		name := tok.(string)
		if _, dup := members[name]; dup {
			return nil, fmt.Errorf("duplicate member %q", name)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, errors.New("not a JSON object")
		}
		members[name] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, errors.New("not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the JSON object")
	}
	return members, nil
}
