package wmp

import "context"

// InboundMessageObserver receives a count-style signal for every inbound
// wmp.message.* method an orchestrator Peer intercepts (see
// WithOrchestratorMessages). Implementations typically increment a metric.
// ObserveInboundMessage must not block.
type InboundMessageObserver interface {
	// method is one of MethodMessageDeliver, MethodMessageAck,
	// MethodMessageStatus. refused is true when the Peer answered the
	// message with an error (a deliver Request), false when it was only
	// logged and dropped.
	ObserveInboundMessage(ctx context.Context, method string, refused bool)
}

// OrchestratorMessageOptions configures WithOrchestratorMessages.
type OrchestratorMessageOptions struct {
	// Observer is optional; it is called once per intercepted message.
	Observer InboundMessageObserver
}

// WithOrchestratorMessages makes the Peer behave as a tls-mode orchestrator
// (a party that runs flows and relays nothing) for inbound wmp.message.*:
//
//   - wmp.message.deliver sent as a Request is answered with -31008
//     (Participant not found): there is no participant to deliver to here. A
//     deliver Notification has no response and is only logged and observed.
//   - wmp.message.ack and wmp.message.status are logged and observed, never
//     routed to the Handler.
//
// The Handler's MessageDeliver/MessageAck/MessageStatus are not called for
// these methods. wmp.message.poll is unaffected.
//
// Without this option the Peer is peer-to-peer as before: all three are
// dispatched to the Handler (BaseHandler drops them silently).
func WithOrchestratorMessages(opts OrchestratorMessageOptions) PeerOption {
	return func(p *Peer) { p.orchestrator = &opts }
}

// interceptMessage handles an inbound wmp.message.deliver/ack/status for an
// orchestrator Peer. It returns handled=false when the option is off.
func (p *Peer) interceptMessage(ctx context.Context, method string) (handled bool, err error) {
	if p.orchestrator == nil {
		return false, nil
	}
	refused := method == MethodMessageDeliver && !IsNotificationFromContext(ctx)
	p.logger.Info("inbound message not routed by orchestrator",
		"method", method, "refused", refused, "sender", SenderFromContext(ctx))
	if o := p.orchestrator.Observer; o != nil {
		o.ObserveInboundMessage(ctx, method, refused)
	}
	if refused {
		return true, NewRPCError(ErrParticipantNotFound, nil)
	}
	return true, nil
}
