// Package main demonstrates a minimal WMP echo server over WebSocket.
package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	ws "github.com/sirosfoundation/go-wmp/pkg/wmp/ws"
)

// handler implements the WMP Handler interface.
type handler struct {
	wmp.BaseHandler
}

func (h *handler) SessionCreate(_ context.Context, params *wmp.SessionCreateParams) (*wmp.SessionCreateResult, error) {
	return &wmp.SessionCreateResult{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: "ses-" + params.WMP.Sender},
		Security: params.Security,
	}, nil
}

func (h *handler) MessageDeliver(_ context.Context, params *wmp.MessageDeliverParams) {
	// In a real application, you'd route the message to recipients.
	slog.Info("message received", "session", params.WMP.SessionID, "to", params.To)
}

func main() {
	logger := slog.Default()

	http.HandleFunc("/wmp", func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Upgrade(w, r)
		if err != nil {
			logger.Error("upgrade failed", "error", err)
			return
		}

		peer := wmp.NewPeer(conn, &handler{}, wmp.WithLogger(logger))
		ctx := r.Context()
		if err := peer.Serve(ctx); err != nil {
			logger.Info("peer disconnected", "error", err)
		}
	})

	log.Printf("WMP echo server listening on :8080/wmp")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
