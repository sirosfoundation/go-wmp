// Command wmp-cli is a minimal WMP messaging client for debugging and interop testing.
//
// Usage:
//
//	wmp-cli [--transport=ws|httpsse] connect <url>          Connect to a WMP endpoint
//	wmp-cli [--transport=ws|httpsse] invite  <invitation>   Accept an invitation URI
//
// Transport is auto-detected from the URL scheme (ws:// → ws, https:// → httpsse)
// or can be forced with --transport or the WMP_TRANSPORT env var.
//
// Once connected, the CLI creates a session and enters an interactive loop
// where incoming messages are printed and the user can send messages by typing.
//
// Commands in interactive mode:
//
//	/send <text>      Send a text message to the session
//	/deliver <json>   Send a raw wmp.message.deliver notification
//	/status           Print session status
//	/close            Close session and exit
//	/quit             Exit without closing
//
// Environment variables:
//
//	WMP_SENDER        Override the sender identity (default: wmp-cli-<pid>)
//	WMP_TRANSPORT     Transport type: "ws" (default) or "httpsse"
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/httpsse"
	ws "github.com/sirosfoundation/go-wmp/pkg/wmp/ws"
)

func main() {
	// Parse flags
	transportFlag := flag.String("transport", "", "Transport type: ws (default) or httpsse")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: wmp-cli [--transport=ws|httpsse] <connect|invite> <url|invitation-uri>\n")
		os.Exit(1)
	}

	cmd := args[0]
	target := args[1]

	// Transport selection: flag > env > auto-detect
	transportType := *transportFlag
	if transportType == "" {
		transportType = os.Getenv("WMP_TRANSPORT")
	}

	// Optional sender identity
	sender := os.Getenv("WMP_SENDER")
	if sender == "" {
		sender = fmt.Sprintf("wmp-cli-%d", os.Getpid())
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var endpointURL string
	var invitationNonce string

	switch cmd {
	case "connect":
		endpointURL = target
	case "create-invite":
		// Generate an invitation URI for the given provider
		provider := target
		inv, err := wmp.NewInvitation(provider, sender, 5*time.Minute)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating invitation: %v\n", err)
			os.Exit(1)
		}
		// Set relay from extra arg if provided
		if len(args) > 2 {
			inv.Relay = args[2]
		}
		uri, err := inv.URI()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating URI: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(uri)
		return
	case "invite":
		inv, err := wmp.ParseInvitationURI(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing invitation: %v\n", err)
			os.Exit(1)
		}
		if inv.IsExpired() {
			fmt.Fprintf(os.Stderr, "Warning: invitation has expired\n")
		}
		invitationNonce = inv.Nonce
		fmt.Fprintf(os.Stderr, "Invitation from %s (provider: %s, purpose: %s)\n",
			inv.Sender, inv.Provider, inv.Purpose)

		if inv.Relay != "" {
			endpointURL = inv.Relay
		} else {
			config, err := wmp.DiscoverConfigForIdentifier(ctx, inv.Provider, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error discovering endpoint: %v\n", err)
				os.Exit(1)
			}
			if transportType == "httpsse" {
				endpointURL = config.Endpoints["https"]
				if endpointURL == "" {
					endpointURL = config.Endpoints["rpc"]
				}
			}
			if endpointURL == "" {
				endpointURL = config.Endpoints["websocket"]
			}
			if endpointURL == "" {
				endpointURL = config.Endpoints["relay"]
			}
		}
		if endpointURL == "" {
			fmt.Fprintf(os.Stderr, "Error: no endpoint found\n")
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		os.Exit(1)
	}

	// Auto-detect transport from URL scheme if not specified
	if transportType == "" {
		if strings.HasPrefix(endpointURL, "wss://") || strings.HasPrefix(endpointURL, "ws://") {
			transportType = "ws"
		} else if strings.HasPrefix(endpointURL, "https://") || strings.HasPrefix(endpointURL, "http://") {
			transportType = "httpsse"
		} else {
			transportType = "ws"
		}
	}

	h := &cliHandler{sender: sender}

	var transport wmp.Transport
	var err error

	switch transportType {
	case "ws":
		wsURL := endpointURL
		if strings.HasPrefix(wsURL, "https://") {
			wsURL = "wss://" + wsURL[len("https://"):]
		} else if strings.HasPrefix(wsURL, "http://") {
			wsURL = "ws://" + wsURL[len("http://"):]
		}
		fmt.Fprintf(os.Stderr, "Connecting via WebSocket to %s ...\n", wsURL)
		transport, _, err = ws.Dial(ctx, wsURL, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error connecting: %v\n", err)
			os.Exit(1)
		}

	case "httpsse":
		httpURL := endpointURL
		if strings.HasPrefix(httpURL, "wss://") {
			httpURL = "https://" + httpURL[len("wss://"):]
		} else if strings.HasPrefix(httpURL, "ws://") {
			httpURL = "http://" + httpURL[len("ws://"):]
		}
		fmt.Fprintf(os.Stderr, "Connecting via HTTP+SSE to %s ...\n", httpURL)
		transport = httpsse.NewClientTransport(httpURL)

	default:
		fmt.Fprintf(os.Stderr, "Unknown transport: %s (use 'ws' or 'httpsse')\n", transportType)
		os.Exit(1)
	}

	defer transport.Close()

	peer := wmp.NewPeer(transport, h, wmp.WithLogger(logger))

	// Start serving incoming messages in background
	var wg sync.WaitGroup
	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := peer.Serve(serveCtx); err != nil {
			if serveCtx.Err() == nil {
				fmt.Fprintf(os.Stderr, "\nConnection closed: %v\n", err)
			}
		}
		cancel() // stop the main loop too
	}()

	// Create session
	fmt.Fprintf(os.Stderr, "Creating session...\n")
	var result wmp.SessionCreateResult
	err = peer.Call(ctx, wmp.MethodSessionCreate, &wmp.SessionCreateParams{
		WMP:             wmp.Metadata{Version: wmp.Version, Sender: sender},
		Security:        wmp.SecurityMode{Mode: "tls"},
		InvitationNonce: invitationNonce,
	}, &result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating session: %v\n", err)
		os.Exit(1)
	}

	sessionID := result.WMP.SessionID
	h.sessionID = sessionID
	fmt.Fprintf(os.Stderr, "Session created: %s\n", sessionID)
	fmt.Fprintf(os.Stderr, "Transport: %s\n", transportType)
	fmt.Fprintf(os.Stderr, "Type /help for commands, or just type a message to send.\n\n")

	// If HTTP+SSE, connect SSE stream now that we have a session ID
	if transportType == "httpsse" {
		if t, ok := transport.(*httpsse.Transport); ok {
			if err := t.ConnectSSE(ctx, sessionID); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: SSE connection failed: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "SSE event stream connected.\n")
			}
		}
	}

	// Interactive loop
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Fprint(os.Stderr, "> ")

	for scanner.Scan() {
		line := scanner.Text()
		if ctx.Err() != nil {
			break
		}

		switch {
		case line == "/help":
			fmt.Fprintln(os.Stderr, "Commands:")
			fmt.Fprintln(os.Stderr, "  /send <text>       Send a text message")
			fmt.Fprintln(os.Stderr, "  /deliver <json>    Send raw message.deliver params")
			fmt.Fprintln(os.Stderr, "  /status            Print session info")
			fmt.Fprintln(os.Stderr, "  /close             Close session and exit")
			fmt.Fprintln(os.Stderr, "  /quit              Exit immediately")
			fmt.Fprintln(os.Stderr, "  <text>             Send a text message (shortcut)")

		case line == "/status":
			fmt.Fprintf(os.Stderr, "Session:   %s\n", sessionID)
			fmt.Fprintf(os.Stderr, "Sender:    %s\n", sender)
			fmt.Fprintf(os.Stderr, "Transport: %s\n", transportType)
			fmt.Fprintf(os.Stderr, "Endpoint:  %s\n", endpointURL)

		case line == "/close":
			fmt.Fprintf(os.Stderr, "Closing session...\n")
			_ = peer.Notify(ctx, wmp.MethodSessionClose, &wmp.SessionCloseParams{
				WMP:    wmp.Metadata{Version: wmp.Version, SessionID: sessionID, Sender: sender},
				Reason: wmp.ReasonComplete,
			})
			serveCancel()
			wg.Wait()
			return

		case line == "/quit":
			serveCancel()
			wg.Wait()
			return

		case strings.HasPrefix(line, "/send "):
			text := strings.TrimPrefix(line, "/send ")
			sendMessage(ctx, peer, sessionID, sender, text)

		case strings.HasPrefix(line, "/deliver "):
			raw := strings.TrimPrefix(line, "/deliver ")
			var params wmp.MessageDeliverParams
			if err := json.Unmarshal([]byte(raw), &params); err != nil {
				fmt.Fprintf(os.Stderr, "Invalid JSON: %v\n", err)
			} else {
				if params.WMP.SessionID == "" {
					params.WMP.SessionID = sessionID
				}
				if params.WMP.Sender == "" {
					params.WMP.Sender = sender
				}
				params.WMP.Version = wmp.Version
				if err := peer.Notify(ctx, wmp.MethodMessageDeliver, &params); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "Sent raw deliver\n")
				}
			}

		case line == "":
			// ignore empty lines

		default:
			// Bare text = send as message
			sendMessage(ctx, peer, sessionID, sender, line)
		}

		if ctx.Err() != nil {
			break
		}
		fmt.Fprint(os.Stderr, "> ")
	}

	serveCancel()
	wg.Wait()
}

func sendMessage(ctx context.Context, peer *wmp.Peer, sessionID, sender, text string) {
	now := time.Now()
	err := peer.Notify(ctx, wmp.MethodMessageDeliver, &wmp.MessageDeliverParams{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: sessionID,
			Sender:    sender,
			Timestamp: &now,
		},
		ContentType: "text/plain",
		Body:        json.RawMessage(`"` + text + `"`),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "Sent: %s\n", text)
	}
}

// cliHandler logs all incoming WMP messages to stdout as JSON.
type cliHandler struct {
	wmp.BaseHandler
	sender    string
	sessionID string
}

func (h *cliHandler) SessionCreate(_ context.Context, params *wmp.SessionCreateParams) (*wmp.SessionCreateResult, error) {
	h.printEvent("session.create", params)
	sid := params.WMP.SessionID
	if sid == "" {
		sid = fmt.Sprintf("cli-%d", time.Now().UnixMilli())
	}
	return &wmp.SessionCreateResult{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: sid},
		Security: params.Security,
	}, nil
}

func (h *cliHandler) SessionClose(_ context.Context, params *wmp.SessionCloseParams) {
	h.printEvent("session.close", params)
}

func (h *cliHandler) MessageDeliver(_ context.Context, params *wmp.MessageDeliverParams) {
	h.printEvent("message.deliver", params)
}

func (h *cliHandler) MessageAck(_ context.Context, params *wmp.MessageAckParams) {
	h.printEvent("message.ack", params)
}

func (h *cliHandler) FlowStart(_ context.Context, params *wmp.FlowStartParams) (*wmp.FlowStartResult, error) {
	h.printEvent("flow.start", params)
	return &wmp.FlowStartResult{
		WMP:      wmp.Metadata{Version: wmp.Version},
		FlowID:   params.FlowID,
		FlowType: params.FlowType,
	}, nil
}

func (h *cliHandler) FlowProgress(_ context.Context, params *wmp.FlowProgressParams) {
	h.printEvent("flow.progress", params)
}

func (h *cliHandler) FlowComplete(_ context.Context, params *wmp.FlowCompleteParams) {
	h.printEvent("flow.complete", params)
}

func (h *cliHandler) FlowError(_ context.Context, params *wmp.FlowErrorParams) {
	h.printEvent("flow.error", params)
}

func (h *cliHandler) printEvent(method string, params interface{}) {
	data, _ := json.Marshal(map[string]interface{}{
		"time":   time.Now().Format(time.RFC3339),
		"method": method,
		"params": params,
	})
	fmt.Println(string(data))
}
