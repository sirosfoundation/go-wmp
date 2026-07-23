// Command wmp-cli is an interactive WMP messaging client for debugging and
// interop testing.
//
// Usage:
//
//	wmp-cli [--transport=ws|httpsse]
//
// If stdin is a pipe or file, the CLI executes the supplied commands as
// startup commands and then exits. If stdin is a terminal, the interactive
// prompt is shown immediately after any startup commands.
//
// Transport is auto-detected from URL schemes (ws:// → ws, https:// → httpsse)
// or can be forced with --transport or the WMP_TRANSPORT env var.
//
// Interactive / startup commands:
//
//	/connect <url>            Open a transport to a WMP endpoint
//	/invite <invitation-uri>  Accept an invitation and connect to its relay
//	/join <url>                Connect and create a session
//	/create                    Create a session on the current transport
//	/resume <token>            Resume/rejoin a session using a resumption token
//	/rejoin <session-id> <token>  Alias for /resume with explicit session id
//	/create-invite <provider> [relay]  Print a new invitation URI
//	/send <text>               Send a text message to the session
//	/deliver <json>            Send a raw wmp.message.deliver notification
//	/status                    Print session/transport status
//	/close                     Close the session
//	/disconnect                Close the transport
//	/quit                      Exit immediately
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
	transportFlag := flag.String("transport", "", "Transport type: ws (default) or httpsse")
	flag.Parse()

	transportType := *transportFlag
	if transportType == "" {
		transportType = os.Getenv("WMP_TRANSPORT")
	}

	sender := os.Getenv("WMP_SENDER")
	if sender == "" {
		sender = fmt.Sprintf("wmp-cli-%d", os.Getpid())
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	h := &cliHandler{sender: sender}
	r := &repl{
		ctx:           ctx,
		cancel:        cancel,
		logger:        logger,
		handler:       h,
		sender:        sender,
		transportType: transportType,
	}

	// Read startup commands from stdin when stdin is not a terminal.
	startup := readStartupCommands()
	for _, line := range startup {
		if r.ctx.Err() != nil {
			break
		}
		if !r.execute(line) {
			r.disconnect()
			return
		}
	}

	if isTerminal(os.Stdin) {
		fmt.Fprint(os.Stderr, "\nInteractive mode. Type /help for commands.\n> ")
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			if r.ctx.Err() != nil {
				break
			}
			if !r.execute(line) {
				break
			}
			if r.ctx.Err() == nil {
				fmt.Fprint(os.Stderr, "> ")
			}
		}
	}

	r.disconnect()
}

func readStartupCommands() []string {
	if isTerminal(os.Stdin) {
		return nil
	}
	var lines []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "/repl" {
			break
		}
		lines = append(lines, line)
	}
	return lines
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

type repl struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	logger              *slog.Logger
	mu                  sync.Mutex
	transport           wmp.Transport
	peer                *wmp.Peer
	handler             *cliHandler
	sender              string
	transportType       string
	transportTypeActive string
	endpoint            string
	sessionID           string
	resumptionToken     string
	invitationNonce     string
	serveCancel         context.CancelFunc
	serveWg             sync.WaitGroup
}

func (r *repl) execute(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return true
	}

	parts := strings.Fields(line)
	cmd := parts[0]
	args := parts[1:]

	switch cmd {
	case "/help":
		r.printHelp()
	case "/connect":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: /connect <url>")
			return true
		}
		r.connect(args[0])
	case "/disconnect":
		r.disconnect()
	case "/invite":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: /invite <invitation-uri>")
			return true
		}
		r.invite(args[0])
	case "/join":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: /join <url>")
			return true
		}
		if r.connect(args[0]) {
			r.createSession()
		}
	case "/create":
		r.createSession()
	case "/resume":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: /resume <resumption-token>")
			return true
		}
		r.resumeSession("", args[0])
	case "/rejoin":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: /rejoin <resumption-token> or /rejoin <session-id> <resumption-token>")
			return true
		}
		if len(args) == 1 {
			r.resumeSession("", args[0])
		} else {
			r.resumeSession(args[0], args[1])
		}
	case "/create-invite":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "Usage: /create-invite <provider> [relay]")
			return true
		}
		provider := args[0]
		relay := ""
		if len(args) > 1 {
			relay = args[1]
		}
		inv, err := wmp.NewInvitation(provider, r.sender, 5*time.Minute)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating invitation: %v\n", err)
			return true
		}
		if relay != "" {
			inv.Relay = relay
		}
		uri, err := inv.URI()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating URI: %v\n", err)
			return true
		}
		fmt.Println(uri)
	case "/send":
		text := strings.TrimPrefix(line, cmd+" ")
		r.send(text)
	case "/deliver":
		raw := strings.TrimPrefix(line, cmd+" ")
		r.deliver(raw)
	case "/status":
		r.status()
	case "/close":
		r.closeSession()
	case "/quit":
		return false
	default:
		// Bare text = send a message if a session exists.
		r.send(line)
	}
	return true
}

func (r *repl) printHelp() {
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  /connect <url>            Open transport to a WMP endpoint")
	fmt.Fprintln(os.Stderr, "  /invite <invitation-uri>  Accept invitation and connect")
	fmt.Fprintln(os.Stderr, "  /join <url>               Connect and create a session")
	fmt.Fprintln(os.Stderr, "  /create                   Create a session on current transport")
	fmt.Fprintln(os.Stderr, "  /resume <token>           Resume/rejoin a session")
	fmt.Fprintln(os.Stderr, "  /rejoin <sid> <token>     Resume/rejoin with explicit session id")
	fmt.Fprintln(os.Stderr, "  /create-invite <p> [relay]  Print a new invitation URI")
	fmt.Fprintln(os.Stderr, "  /send <text>              Send a text message")
	fmt.Fprintln(os.Stderr, "  /deliver <json>           Send raw message.deliver params")
	fmt.Fprintln(os.Stderr, "  /status                   Print session/transport status")
	fmt.Fprintln(os.Stderr, "  /close                    Close the session")
	fmt.Fprintln(os.Stderr, "  /disconnect               Close the transport")
	fmt.Fprintln(os.Stderr, "  /quit                     Exit")
	fmt.Fprintln(os.Stderr, "  <text>                    Send a text message (if in session)")
}

func (r *repl) connect(endpointURL string) bool {
	r.disconnect()

	transportType := r.transportType
	if transportType == "" {
		switch {
		case strings.HasPrefix(endpointURL, "wss://"), strings.HasPrefix(endpointURL, "ws://"):
			transportType = "ws"
		case strings.HasPrefix(endpointURL, "https://"), strings.HasPrefix(endpointURL, "http://"):
			transportType = "httpsse"
		default:
			transportType = "ws"
		}
	}

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
		allowInsecure := strings.HasPrefix(wsURL, "ws://")
		transport, _, err = ws.Dial(r.ctx, wsURL, nil, allowInsecure)
	case "httpsse":
		httpURL := endpointURL
		if strings.HasPrefix(httpURL, "wss://") {
			httpURL = "https://" + httpURL[len("wss://"):]
		} else if strings.HasPrefix(httpURL, "ws://") {
			httpURL = "http://" + httpURL[len("ws://"):]
		}
		fmt.Fprintf(os.Stderr, "Connecting via HTTP+SSE to %s ...\n", httpURL)
		transport, err = httpsse.NewClientTransport(httpURL)
	default:
		fmt.Fprintf(os.Stderr, "Unknown transport: %s\n", transportType)
		return false
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting: %v\n", err)
		return false
	}

	peer := wmp.NewPeer(transport, r.handler, wmp.WithLogger(r.logger))

	serveCtx, serveCancel := context.WithCancel(r.ctx)
	r.serveWg.Add(1)
	go func() {
		defer r.serveWg.Done()
		if err := peer.Serve(serveCtx); err != nil {
			if serveCtx.Err() == nil {
				fmt.Fprintf(os.Stderr, "\nConnection closed: %v\n", err)
			}
		}
	}()

	r.mu.Lock()
	r.transport = transport
	r.peer = peer
	r.endpoint = endpointURL
	r.transportTypeActive = transportType
	r.serveCancel = serveCancel
	r.invitationNonce = ""
	r.mu.Unlock()

	fmt.Fprintf(os.Stderr, "Connected.\n")
	return true
}

func (r *repl) disconnect() {
	r.mu.Lock()
	transport := r.transport
	serveCancel := r.serveCancel
	r.transport = nil
	r.peer = nil
	r.sessionID = ""
	r.resumptionToken = ""
	r.invitationNonce = ""
	r.endpoint = ""
	r.transportTypeActive = ""
	r.serveCancel = nil
	r.mu.Unlock()

	if serveCancel != nil {
		serveCancel()
	}
	if transport != nil {
		_ = transport.Close()
	}
	r.serveWg.Wait()
}

func (r *repl) invite(uri string) {
	inv, err := wmp.ParseInvitationURI(uri)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing invitation: %v\n", err)
		return
	}
	if inv.IsExpired() {
		fmt.Fprintf(os.Stderr, "Warning: invitation has expired\n")
	}
	fmt.Fprintf(os.Stderr, "Invitation from %s (provider: %s, purpose: %s)\n",
		inv.Sender, inv.Provider, inv.Purpose)

	var endpointURL string
	if inv.Relay != "" {
		endpointURL = inv.Relay
	} else {
		transportType := r.transportType
		config, err := wmp.DiscoverConfigForIdentifier(r.ctx, inv.Provider, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error discovering endpoint: %v\n", err)
			return
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
		return
	}

	r.mu.Lock()
	r.invitationNonce = inv.Nonce
	r.mu.Unlock()

	if r.connect(endpointURL) {
		r.createSession()
	}
}

func (r *repl) createSession() {
	peer := r.currentPeer()
	if peer == nil {
		fmt.Fprintf(os.Stderr, "Not connected. Use /connect or /invite first.\n")
		return
	}

	fmt.Fprintf(os.Stderr, "Creating session...\n")
	var nonce string
	r.mu.Lock()
	nonce = r.invitationNonce
	r.mu.Unlock()

	var result wmp.SessionCreateResult
	err := peer.Call(r.ctx, wmp.MethodSessionCreate, &wmp.SessionCreateParams{
		WMP:             wmp.Metadata{Version: wmp.Version, Sender: r.sender},
		Security:        wmp.SecurityMode{Mode: "tls"},
		InvitationNonce: nonce,
	}, &result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating session: %v\n", err)
		return
	}

	r.mu.Lock()
	r.sessionID = result.WMP.SessionID
	r.resumptionToken = result.ResumptionToken
	r.handler.sessionID = result.WMP.SessionID
	r.mu.Unlock()

	fmt.Fprintf(os.Stderr, "Session created: %s\n", result.WMP.SessionID)
	if result.ResumptionToken != "" {
		fmt.Fprintf(os.Stderr, "Resumption token: %s\n", result.ResumptionToken)
	}

	r.connectSSE()
}

func (r *repl) resumeSession(sessionID, token string) {
	peer := r.currentPeer()
	if peer == nil {
		fmt.Fprintf(os.Stderr, "Not connected. Use /connect first.\n")
		return
	}

	fmt.Fprintf(os.Stderr, "Resuming session...\n")
	var result wmp.SessionResumeResult
	err := peer.Call(r.ctx, wmp.MethodSessionResume, &wmp.SessionResumeParams{
		WMP:             wmp.Metadata{Version: wmp.Version, Sender: r.sender},
		SessionID:       sessionID,
		ResumptionToken: token,
	}, &result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resuming session: %v\n", err)
		return
	}

	newSessionID := result.WMP.SessionID
	if newSessionID == "" {
		newSessionID = sessionID
	}

	r.mu.Lock()
	r.sessionID = newSessionID
	r.resumptionToken = result.ResumptionToken
	r.handler.sessionID = newSessionID
	r.mu.Unlock()

	fmt.Fprintf(os.Stderr, "Session resumed: %s\n", newSessionID)
	r.connectSSE()
}

func (r *repl) connectSSE() {
	r.mu.Lock()
	transport := r.transport
	sessionID := r.sessionID
	transportType := r.transportTypeActive
	r.mu.Unlock()

	if transportType != "httpsse" {
		return
	}
	if t, ok := transport.(*httpsse.Transport); ok && sessionID != "" {
		if err := t.ConnectSSE(r.ctx, sessionID); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: SSE connection failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "SSE event stream connected.\n")
		}
	}
}

func (r *repl) closeSession() {
	peer, sessionID := r.currentPeerAndSession()
	if peer == nil {
		fmt.Fprintf(os.Stderr, "Not connected.\n")
		return
	}
	if sessionID == "" {
		fmt.Fprintf(os.Stderr, "No active session.\n")
		return
	}

	fmt.Fprintf(os.Stderr, "Closing session...\n")
	_ = peer.Notify(r.ctx, wmp.MethodSessionClose, &wmp.SessionCloseParams{
		WMP:    wmp.Metadata{Version: wmp.Version, SessionID: sessionID, Sender: r.sender},
		Reason: wmp.ReasonComplete,
	})

	r.mu.Lock()
	r.sessionID = ""
	r.resumptionToken = ""
	r.handler.sessionID = ""
	r.mu.Unlock()
}

func (r *repl) send(text string) {
	peer, sessionID := r.currentPeerAndSession()
	if peer == nil {
		fmt.Fprintf(os.Stderr, "Not connected.\n")
		return
	}
	if sessionID == "" {
		fmt.Fprintf(os.Stderr, "No active session. Use /create or /resume.\n")
		return
	}

	now := time.Now()
	err := peer.Notify(r.ctx, wmp.MethodMessageDeliver, &wmp.MessageDeliverParams{
		WMP: wmp.Metadata{
			Version:   wmp.Version,
			SessionID: sessionID,
			Sender:    r.sender,
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

func (r *repl) deliver(raw string) {
	peer, sessionID := r.currentPeerAndSession()
	if peer == nil {
		fmt.Fprintf(os.Stderr, "Not connected.\n")
		return
	}
	if sessionID == "" {
		fmt.Fprintf(os.Stderr, "No active session.\n")
		return
	}

	var params wmp.MessageDeliverParams
	if err := json.Unmarshal([]byte(raw), &params); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid JSON: %v\n", err)
		return
	}
	if params.WMP.SessionID == "" {
		params.WMP.SessionID = sessionID
	}
	if params.WMP.Sender == "" {
		params.WMP.Sender = r.sender
	}
	params.WMP.Version = wmp.Version
	if err := peer.Notify(r.ctx, wmp.MethodMessageDeliver, &params); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "Sent raw deliver\n")
	}
}

func (r *repl) status() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peer == nil {
		fmt.Fprintf(os.Stderr, "Not connected.\n")
		return
	}
	fmt.Fprintf(os.Stderr, "Connected:  yes\n")
	fmt.Fprintf(os.Stderr, "Endpoint:   %s\n", r.endpoint)
	fmt.Fprintf(os.Stderr, "Transport:  %s\n", r.transportTypeActive)
	fmt.Fprintf(os.Stderr, "Sender:     %s\n", r.sender)
	if r.sessionID == "" {
		fmt.Fprintf(os.Stderr, "Session:    none\n")
	} else {
		fmt.Fprintf(os.Stderr, "Session:    %s\n", r.sessionID)
	}
	if r.resumptionToken != "" {
		fmt.Fprintf(os.Stderr, "Resume:     %s\n", r.resumptionToken)
	}
}

func (r *repl) currentPeer() *wmp.Peer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.peer
}

func (r *repl) currentPeerAndSession() (*wmp.Peer, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.peer, r.sessionID
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
