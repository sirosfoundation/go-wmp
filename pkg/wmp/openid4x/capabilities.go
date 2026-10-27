package openid4x

import (
	"encoding/json"
	"errors"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// CapabilityConfig describes the capability descriptors an endpoint advertises
// (profile §2.1-2.3). A nil member means the capability is not advertised.
type CapabilityConfig struct {
	OID4VCI         *OID4VCICapability
	OID4VP          *OID4VPCapability
	TransactionData *wmp.TransactionDataCap
}

// CapabilityDescriptors builds the wmp.Capabilities map for session
// negotiation from cfg: "oid4vci", "oid4vp" and "transaction_data" members,
// each present only when configured. Required list members are emitted as []
// rather than null when empty.
//
// It returns an error for a transaction_data descriptor that lists no version:
// such a descriptor would advertise a capability that no peer can use.
func CapabilityDescriptors(cfg CapabilityConfig) (wmp.Capabilities, error) {
	caps := wmp.Capabilities{}
	if cfg.OID4VCI != nil {
		v := *cfg.OID4VCI
		v.SupportedGrants = nonNil(v.SupportedGrants)
		v.SupportedFormats = nonNil(v.SupportedFormats)
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		caps[CapabilityOID4VCI] = raw
	}
	if cfg.OID4VP != nil {
		v := *cfg.OID4VP
		v.SupportedResponseModes = nonNil(v.SupportedResponseModes)
		v.SupportedFormats = nonNil(v.SupportedFormats)
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		caps[CapabilityOID4VP] = raw
	}
	if cfg.TransactionData != nil {
		if len(cfg.TransactionData.Versions) == 0 {
			return nil, errors.New("openid4x: transaction_data descriptor lists no versions")
		}
		raw, err := json.Marshal(cfg.TransactionData)
		if err != nil {
			return nil, err
		}
		caps[wmp.CapabilityTransactionData] = raw
	}
	return caps, nil
}

// CapabilityDescriptors returns the descriptors for this profile's Config
// (OID4VCI, OID4VP and TransactionData).
func (p *Profile) CapabilityDescriptors() (wmp.Capabilities, error) {
	return CapabilityDescriptors(CapabilityConfig{
		OID4VCI:         p.config.OID4VCI,
		OID4VP:          p.config.OID4VP,
		TransactionData: p.config.TransactionData,
	})
}

// TransactionDataUnsupportedData is the data member for refusing
// transaction_data towards a wallet that lacks the capability: -31005 with
// {"unsupported":"transaction_data"}, plus "redirect_uri" when non-empty so
// the verifier-side redirect is not lost (additive to profile §2.3).
func TransactionDataUnsupportedData(redirectURI string) map[string]any {
	var extra map[string]any
	if redirectURI != "" {
		extra = map[string]any{"redirect_uri": redirectURI}
	}
	return wmp.UnsupportedData(wmp.CapabilityTransactionData, extra)
}

// NewTransactionDataUnsupportedError returns the -31005 error carrying
// TransactionDataUnsupportedData.
func NewTransactionDataUnsupportedError(redirectURI string) *wmp.RPCError {
	return wmp.NewRPCError(wmp.ErrCapabilityNotSupported, TransactionDataUnsupportedData(redirectURI))
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
