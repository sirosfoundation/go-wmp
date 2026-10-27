package wmp_test

import (
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmptest"
)

func TestMemorySessionStore_Conformance(t *testing.T) {
	wmptest.RunSessionStoreSuite(t, func() wmp.SessionStore { return wmp.NewMemorySessionStore() })
}
