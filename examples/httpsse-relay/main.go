// Command httpsse-relay is a standalone WMP relay using the HTTP+SSE transport.
//
// It hosts authoritative session state and exposes:
//   - POST /      JSON-RPC request/response for WMP methods
//   - GET  /events SSE stream for server-initiated messages
//   - GET  /.well-known/mls-key-packages published MLS KeyPackages
//   - GET  /health health check
//
// The relay supports plain HTTP (for deployment behind a TLS-terminating
// reverse proxy such as Fly.io, Caddy, or nginx) and direct HTTPS (for local
// development with a provided certificate).
//
// Environment variables:
//
//	PORT       Listen port (default: 8080)
//	TLS_CERT   Path to TLS certificate (optional)
//	TLS_KEY    Path to TLS private key (optional)
//	LOG_LEVEL  slog level: debug, info, warn, error (default: info)
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/httpsse"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/mls"
)

func main() {
	logger := newLogger(os.Getenv("LOG_LEVEL"))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	tlsCert := os.Getenv("TLS_CERT")
	tlsKey := os.Getenv("TLS_KEY")

	sessions := wmp.NewMemorySessionStore()
	mlsProvider := mls.NewNoopMLSProvider(mls.WithAllowInsecure(true))

	handler := &relayHandler{
		sessions: sessions,
		logger:   logger,
	}

	server := httpsse.NewServerHandler(handler,
		wmp.WithLogger(logger),
		wmp.WithSessionStore(sessions),
		wmp.WithProfile(handler),
		wmp.WithProfile(mls.NewProfile(mls.NewNoopMLSHandler())),
	)

	mux := http.NewServeMux()
	mux.Handle("/", server)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/.well-known/mls-key-packages", keyPackagesHandler(logger, mlsProvider))

	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go cleanupLoop(logger, sessions)

	scheme := "http"
	if tlsCert != "" && tlsKey != "" {
		scheme = "https"
	}
	logger.Info("httpsse relay listening", "addr", httpServer.Addr, "scheme", scheme)

	var err error
	if scheme == "https" {
		err = httpServer.ListenAndServeTLS(tlsCert, tlsKey)
	} else {
		err = httpServer.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

// relayHandler implements wmp.Handler and wmp.Profile. It owns the
// authoritative session state and optionally broadcasts message deliveries
// to every client attached to a session via SSE.
type relayHandler struct {
	wmp.BaseHandler
	mu       sync.Mutex
	pc       wmp.PeerContext
	sessions wmp.SessionStore
	logger   *slog.Logger
}

func (h *relayHandler) Name() string           { return "httpsse-relay" }
func (h *relayHandler) Capabilities() []string { return []string{"messaging", "mls"} }

func (h *relayHandler) Init(ctx wmp.PeerContext) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pc = ctx
	return nil
}

func (h *relayHandler) SessionCreate(ctx context.Context, params *wmp.SessionCreateParams) (*wmp.SessionCreateResult, error) {
	sessionID := params.WMP.SessionID
	if sessionID == "" {
		sessionID = generateID("sess")
	}
	resumptionToken := generateToken()

	sess := &wmp.Session{
		ID:              sessionID,
		Participants:    params.Participants,
		Capabilities:    params.CapabilitiesOffered,
		Security:        params.Security,
		Metadata:        map[string]string{"creator": params.WMP.Sender},
		ResumptionToken: resumptionToken,
		CreatedAt:       time.Now(),
	}
	if params.TTL > 0 {
		sess.ExpiresAt = sess.CreatedAt.Add(time.Duration(params.TTL) * time.Second)
	}
	if err := h.sessions.Create(sess); err != nil {
		return nil, err
	}

	h.logger.Info("session created",
		"session_id", sessionID,
		"sender", params.WMP.Sender,
		"participants", params.Participants,
	)

	return &wmp.SessionCreateResult{
		WMP:             wmp.Metadata{Version: wmp.Version, SessionID: sessionID, Sender: "relay"},
		Capabilities:    params.CapabilitiesOffered,
		Security:        params.Security,
		ResumptionToken: resumptionToken,
	}, nil
}

func (h *relayHandler) SessionResume(ctx context.Context, params *wmp.SessionResumeParams) (*wmp.SessionResumeResult, error) {
	var sess *wmp.Session
	var ok bool
	if params.SessionID != "" {
		sess, ok = h.sessions.Get(params.SessionID)
	} else {
		// Token-only resume lookup. This matches clients such as wmp-cli that
		// may only have the resumption token. A production relay should
		// additionally rotate tokens and accept them through a short grace
		// window or require the session id.
		sessions, err := h.sessions.List()
		if err == nil {
			for _, s := range sessions {
				if s.ResumptionToken == params.ResumptionToken {
					sess = s
					ok = true
					break
				}
			}
		}
	}

	if !ok || sess.IsExpired() {
		return nil, wmp.NewRPCError(wmp.ErrSessionNotFound, map[string]string{
			"reason": "session not found or expired",
		})
	}
	if sess.ResumptionToken != params.ResumptionToken {
		return nil, wmp.NewRPCError(wmp.ErrNotAuthorized, map[string]string{
			"reason": "invalid resumption token",
		})
	}

	h.logger.Info("session resumed", "session_id", sess.ID, "sender", params.WMP.Sender)

	return &wmp.SessionResumeResult{
		WMP:             wmp.Metadata{Version: wmp.Version, SessionID: sess.ID, Sender: "relay"},
		Resumed:         true,
		ResumptionToken: sess.ResumptionToken,
		Capabilities:    sess.Capabilities,
		Security:        sess.Security,
	}, nil
}

func (h *relayHandler) SessionClose(ctx context.Context, params *wmp.SessionCloseParams) {
	_ = h.sessions.Delete(params.WMP.SessionID)
	h.logger.Info("session closed", "session_id", params.WMP.SessionID, "reason", params.Reason)
}

func (h *relayHandler) MessageDeliver(ctx context.Context, params *wmp.MessageDeliverParams) {
	h.logger.Info("message delivered",
		"session_id", params.WMP.SessionID,
		"sender", params.WMP.Sender,
		"content_type", params.ContentType,
		"to", params.To,
	)

	// Broadcast the delivery to every SSE client attached to this session.
	// The sender will also receive the echo; this matches group-messaging
	// semantics where every participant sees every message.
	h.mu.Lock()
	pc := h.pc
	h.mu.Unlock()
	if pc != nil {
		_ = pc.Notify(ctx, wmp.MethodMessageDeliver, params)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func keyPackagesHandler(logger *slog.Logger, provider mls.MLSProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kp, err := provider.GenerateKeyPackage(mls.CipherSuiteX25519AES128GCM)
		if err != nil {
			logger.Error("failed to generate key package", "error", err)
			http.Error(w, "key package generation failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mls.KeyPackagesResponse{KeyPackages: []mls.KeyPackage{*kp}})
	}
}

func cleanupLoop(logger *slog.Logger, store wmp.SessionStore) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		count, err := store.Cleanup()
		if err != nil {
			logger.Error("session cleanup failed", "error", err)
			continue
		}
		if count > 0 {
			logger.Info("cleaned up expired sessions", "count", count)
		}
	}
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "info", "":
		lv = slog.LevelInfo
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
}

func generateID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + "-" + base64.RawURLEncoding.EncodeToString(b)
}

func generateToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
