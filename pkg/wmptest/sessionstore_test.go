package wmptest_test

import (
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmptest"
)

func TestRunSessionStoreSuite_Memory(t *testing.T) {
	wmptest.RunSessionStoreSuite(t, func() wmp.SessionStore { return wmp.NewMemorySessionStore() })
}

// plainStore hides TokenRotator so the suite's rotator-less path is covered.
type plainStore struct{ wmp.SessionStore }

func TestRunSessionStoreSuite_NoRotator(t *testing.T) {
	wmptest.RunSessionStoreSuite(t, func() wmp.SessionStore { return plainStore{wmp.NewMemorySessionStore()} })
}
