// Package wmptest provides reusable conformance tests for implementations of
// go-wmp extension interfaces.
package wmptest

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// RunSessionStoreSuite runs the SessionStore contract against stores made by
// newStore (called once per subtest; each store must start empty). If the
// store also implements wmp.TokenRotator the rotation contract is run too.
//
// The suite does not assume whether a store returns copies or shared
// pointers: after every mutation it re-reads through Get.
func RunSessionStoreSuite(t *testing.T, newStore func() wmp.SessionStore) {
	t.Helper()

	sess := func(id string) *wmp.Session {
		return &wmp.Session{
			ID:                       id,
			Participants:             []string{"a", "b"},
			Security:                 wmp.SecurityMode{Mode: "tls"},
			Metadata:                 map[string]string{"k": "v"},
			ResumptionToken:          "tok-" + id,
			ResumptionTokenExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second),
			Owner:                    "tenant/alice",
			CreatedAt:                time.Now().Truncate(time.Second),
			ExpiresAt:                time.Now().Add(time.Hour).Truncate(time.Second),
		}
	}

	t.Run("CreateGetRoundTrip", func(t *testing.T) {
		s := newStore()
		in := sess("s1")
		if err := s.Create(in); err != nil {
			t.Fatal(err)
		}
		got, ok := s.Get("s1")
		if !ok {
			t.Fatal("Get: not found")
		}
		if got.ID != "s1" || got.Owner != "tenant/alice" || got.ResumptionToken != "tok-s1" ||
			got.Metadata["k"] != "v" || len(got.Participants) != 2 || got.Security.Mode != "tls" {
			t.Fatalf("round trip lost fields: %+v", got)
		}
		if !got.ResumptionTokenExpiresAt.Equal(in.ResumptionTokenExpiresAt) || !got.ExpiresAt.Equal(in.ExpiresAt) {
			t.Fatalf("round trip lost times: %+v", got)
		}
	})

	t.Run("GetMissing", func(t *testing.T) {
		if _, ok := newStore().Get("nope"); ok {
			t.Fatal("found nonexistent session")
		}
	})

	t.Run("UpdatePersistsOwnerAndToken", func(t *testing.T) {
		s := newStore()
		if err := s.Create(sess("s1")); err != nil {
			t.Fatal(err)
		}
		got, _ := s.Get("s1")
		upd := *got
		upd.Owner = "tenant/bob"
		upd.ResumptionToken = "rotated"
		if err := s.Update(&upd); err != nil {
			t.Fatal(err)
		}
		got, ok := s.Get("s1")
		if !ok || got.Owner != "tenant/bob" || got.ResumptionToken != "rotated" {
			t.Fatalf("update not persisted: %+v ok=%v", got, ok)
		}
	})

	t.Run("DeleteAndDeleteMissing", func(t *testing.T) {
		s := newStore()
		if err := s.Create(sess("s1")); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete("s1"); err != nil {
			t.Fatal(err)
		}
		if _, ok := s.Get("s1"); ok {
			t.Fatal("deleted session still present")
		}
		if err := s.Delete("s1"); err != nil {
			t.Fatalf("deleting a missing session must not error: %v", err)
		}
	})

	t.Run("GetByMetadataSkipsExpired", func(t *testing.T) {
		s := newStore()
		live, other, dead := sess("live"), sess("other"), sess("dead")
		other.Metadata = map[string]string{"k": "x"}
		dead.ExpiresAt = time.Now().Add(-time.Minute)
		for _, x := range []*wmp.Session{live, other, dead} {
			if err := s.Create(x); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.GetByMetadata("k", "v")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].ID != "live" {
			t.Fatalf("GetByMetadata: got %v", ids(got))
		}
	})

	t.Run("ListSkipsExpired", func(t *testing.T) {
		s := newStore()
		dead := sess("dead")
		dead.ExpiresAt = time.Now().Add(-time.Minute)
		for _, x := range []*wmp.Session{sess("a"), sess("b"), dead} {
			if err := s.Create(x); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.List()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("List: got %v", ids(got))
		}
	})

	t.Run("CleanupRemovesOnlyExpired", func(t *testing.T) {
		s := newStore()
		dead := sess("dead")
		dead.ExpiresAt = time.Now().Add(-time.Minute)
		for _, x := range []*wmp.Session{sess("live"), dead} {
			if err := s.Create(x); err != nil {
				t.Fatal(err)
			}
		}
		n, err := s.Cleanup()
		if err != nil || n != 1 {
			t.Fatalf("Cleanup: n=%d err=%v", n, err)
		}
		if _, ok := s.Get("dead"); ok {
			t.Fatal("expired session survived Cleanup")
		}
		if _, ok := s.Get("live"); !ok {
			t.Fatal("live session removed by Cleanup")
		}
	})

	if _, ok := newStore().(wmp.TokenRotator); !ok {
		return
	}
	runRotatorSuite(t, newStore, sess)
}

func runRotatorSuite(t *testing.T, newStore func() wmp.SessionStore, sess func(string) *wmp.Session) {
	rot := func(s wmp.SessionStore) wmp.TokenRotator { return s.(wmp.TokenRotator) }

	t.Run("Rotate/SuccessIsOneTimeUse", func(t *testing.T) {
		s := newStore()
		if err := s.Create(sess("s1")); err != nil {
			t.Fatal(err)
		}
		exp := time.Now().Add(2 * time.Hour).Truncate(time.Second)
		got, err := rot(s).RotateResumptionToken("s1", "tok-s1", "tok-new", exp)
		if err != nil {
			t.Fatal(err)
		}
		if got.ResumptionToken != "tok-new" || !got.ResumptionTokenExpiresAt.Equal(exp) {
			t.Fatalf("returned session: %+v", got)
		}
		stored, _ := s.Get("s1")
		if stored.ResumptionToken != "tok-new" || stored.Owner != "tenant/alice" {
			t.Fatalf("stored session: %+v", stored)
		}
		// The old token is dead: replaying it must fail.
		if _, err := rot(s).RotateResumptionToken("s1", "tok-s1", "tok-x", exp); !errors.Is(err, wmp.ErrTokenMismatch) {
			t.Fatalf("replay of consumed token: got %v, want ErrTokenMismatch", err)
		}
		if stored, _ = s.Get("s1"); stored.ResumptionToken != "tok-new" {
			t.Fatal("failed rotation changed the token")
		}
	})

	t.Run("Rotate/Mismatch", func(t *testing.T) {
		s := newStore()
		if err := s.Create(sess("s1")); err != nil {
			t.Fatal(err)
		}
		for _, old := range []string{"wrong", "", "tok-s1x", "tok-s"} {
			if _, err := rot(s).RotateResumptionToken("s1", old, "n", time.Time{}); !errors.Is(err, wmp.ErrTokenMismatch) {
				t.Fatalf("old=%q: got %v, want ErrTokenMismatch", old, err)
			}
		}
	})

	t.Run("Rotate/EmptyOldNeverMatchesEmptyStored", func(t *testing.T) {
		s := newStore()
		x := sess("s1")
		x.ResumptionToken = ""
		if err := s.Create(x); err != nil {
			t.Fatal(err)
		}
		if _, err := rot(s).RotateResumptionToken("s1", "", "n", time.Time{}); !errors.Is(err, wmp.ErrTokenMismatch) {
			t.Fatalf("got %v, want ErrTokenMismatch", err)
		}
	})

	t.Run("Rotate/UnknownSession", func(t *testing.T) {
		if _, err := rot(newStore()).RotateResumptionToken("nope", "t", "n", time.Time{}); !errors.Is(err, wmp.ErrNoSuchSession) {
			t.Fatalf("got %v, want ErrNoSuchSession", err)
		}
	})

	t.Run("Rotate/ExpiredSession", func(t *testing.T) {
		s := newStore()
		x := sess("s1")
		x.ExpiresAt = time.Now().Add(-time.Minute)
		if err := s.Create(x); err != nil {
			t.Fatal(err)
		}
		if _, err := rot(s).RotateResumptionToken("s1", "tok-s1", "n", time.Time{}); !errors.Is(err, wmp.ErrNoSuchSession) {
			t.Fatalf("got %v, want ErrNoSuchSession", err)
		}
	})

	t.Run("Rotate/ExpiredToken", func(t *testing.T) {
		s := newStore()
		x := sess("s1")
		x.ResumptionTokenExpiresAt = time.Now().Add(-time.Second)
		if err := s.Create(x); err != nil {
			t.Fatal(err)
		}
		if _, err := rot(s).RotateResumptionToken("s1", "tok-s1", "n", time.Time{}); !errors.Is(err, wmp.ErrTokenExpired) {
			t.Fatalf("got %v, want ErrTokenExpired", err)
		}
		if got, _ := s.Get("s1"); got.ResumptionToken != "tok-s1" {
			t.Fatal("expired-token rotation changed the token")
		}
	})

	t.Run("Rotate/ZeroTokenExpiryNeverExpires", func(t *testing.T) {
		s := newStore()
		x := sess("s1")
		x.ResumptionTokenExpiresAt = time.Time{}
		if err := s.Create(x); err != nil {
			t.Fatal(err)
		}
		if _, err := rot(s).RotateResumptionToken("s1", "tok-s1", "n", time.Time{}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Rotate/ConcurrentExactlyOneWins", func(t *testing.T) {
		s := newStore()
		if err := s.Create(sess("s1")); err != nil {
			t.Fatal(err)
		}
		const n = 32
		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			winners []string
			losers  int
			start   = make(chan struct{})
		)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				nt := fmt.Sprintf("new-%d", i)
				_, err := rot(s).RotateResumptionToken("s1", "tok-s1", nt, time.Time{})
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					winners = append(winners, nt)
				case errors.Is(err, wmp.ErrTokenMismatch):
					losers++
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}(i)
		}
		close(start)
		wg.Wait()
		if len(winners) != 1 || losers != n-1 {
			t.Fatalf("winners=%v losers=%d, want exactly one winner", winners, losers)
		}
		if got, _ := s.Get("s1"); got.ResumptionToken != winners[0] {
			t.Fatalf("stored token %q, winner %q", got.ResumptionToken, winners[0])
		}
	})
}

func ids(ss []*wmp.Session) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.ID)
	}
	return out
}
