package server

import (
	"testing"
	"time"
)

func TestLoginLimiter(t *testing.T) {
	l := newLoginLimiter(2, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }

	if ok, _ := l.allow("10.0.0.1"); !ok {
		t.Fatal("first attempt must pass")
	}
	if ok, _ := l.allow("10.0.0.1"); !ok {
		t.Fatal("second attempt must pass")
	}
	ok, wait := l.allow("10.0.0.1")
	if ok || wait <= 0 {
		t.Fatalf("third attempt must be throttled, ok=%v wait=%v", ok, wait)
	}
	// Another client is unaffected.
	if ok, _ := l.allow("10.0.0.2"); !ok {
		t.Fatal("a different client must not be throttled")
	}
	// A successful login clears the counter.
	l.reset("10.0.0.1")
	if ok, _ := l.allow("10.0.0.1"); !ok {
		t.Fatal("reset must allow again")
	}
	// The window expires.
	now = now.Add(2 * time.Minute)
	if ok, _ := l.allow("10.0.0.1"); !ok {
		t.Fatal("expired window must allow again")
	}
}
