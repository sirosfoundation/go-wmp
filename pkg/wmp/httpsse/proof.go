package httpsse

import (
	"crypto/subtle"
	"net/http"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/proof"
)

// ProofConfig makes a secured handler require the per-request proof of WMP
// Core section 4.4.8.
type ProofConfig struct {
	// Verifier checks the proofs. Required.
	Verifier *proof.Verifier

	// Principal maps a verified proof to the Principal it authenticates,
	// from the leaf certificate's SAN or the key id. The session lookup
	// then admits the request only on a session that Principal created,
	// which is the identity match of the verification's last step: a proof
	// of another identity is answered as an unknown session (-31000, or 404
	// on the event stream), as the transport requires for a session the
	// caller does not own. An error, or a Principal with no Subject, is
	// answered with 401. Required.
	Principal func(p *proof.Proof) (wmp.Principal, error)

	// URL returns the URL the client sent r to. Set it behind a proxy that
	// rewrites the scheme, host or path. Default: proof.RequestURL.
	URL func(r *http.Request) string
}

type proofKey struct{}

// proofState is what serveSecured learned about the proof of a request.
type proofState struct {
	presented bool
	sessionID string // the verified "sid"
}

// authenticate verifies the proof of r, if it carries one. ok is false when
// there is none (state.presented false) or it does not pass (true).
func (c *ProofConfig) authenticate(r *http.Request) (wmp.Principal, proofState, bool) {
	if _, presented := proof.FromHeader(r.Header.Get("Authorization")); !presented {
		return wmp.Principal{}, proofState{}, false
	}
	state := proofState{presented: true}
	if c.Verifier == nil || c.Principal == nil {
		return wmp.Principal{}, state, false
	}
	url := ""
	if c.URL != nil {
		url = c.URL(r)
	}
	verified, err := c.Verifier.VerifyRequest(r, url, "")
	if err != nil {
		return wmp.Principal{}, state, false
	}
	p, err := c.Principal(verified)
	if err != nil || p.Key() == "" {
		return wmp.Principal{}, state, false
	}
	state.sessionID = verified.SessionID
	return p, state, true
}

// proofBinds reports whether the request may act on session id: a handler
// that requires proofs admits a request naming a session only with a
// verified proof whose "sid" is that session. A request that names none
// (wmp.session.create) is admitted only as authenticated by Authenticate: a
// proof is bound to an existing session and never creates one. A request
// that did not come through ServeHTTP (ServeAuthenticated, WithPrincipal)
// was authenticated by the embedder and is not checked here.
func proofBinds(r *http.Request, id string) bool {
	state, required := r.Context().Value(proofKey{}).(proofState)
	if !required {
		return true
	}
	if id == "" {
		return !state.presented
	}
	return state.presented && subtle.ConstantTimeCompare([]byte(state.sessionID), []byte(id)) == 1
}
