package qerds_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/proof"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/qerds"
)

// The sender's credential and MLS engine come from the application.
var (
	privateKey crypto.Signer
	chain      []*x509.Certificate
	engine     qerds.GroupProvider
)

func ExampleSend() {
	ctx := context.Background()

	signer, err := proof.NewSigner(privateKey) // the leaf's key, any crypto.Signer
	if err != nil {
		log.Fatal(err)
	}

	result, err := qerds.Send(ctx, qerds.Config{
		Endpoint:   "https://erds.example.com/wmp",
		Sender:     "ebcore:iso6523:0007:5595421925",
		Recipients: []string{"ebcore:iso6523:0106:99900817"},
		Credential: qerds.Credential{Chain: chain, Signer: signer}, // leaf first
		Auth:       wmp.AuthTypeDPoP,                               // or wmp.AuthTypeMTLS
		Message:    qerds.Message{Body: json.RawMessage(`{"text":"the consignment"}`)},
		MLS:        engine,
	})
	var failed *qerds.Error
	if errors.As(err, &failed) {
		log.Fatalf("stopped at %s: %v", failed.Step, failed.Err)
	}
	log.Println(result.Confirmed, len(result.Evidence), result.Message.ID)
}
