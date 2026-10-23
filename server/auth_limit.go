package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// loginLimiter throttles password attempts per client IP. The admin account is
// single and the password is the only barrier to a platform that can execute
// commands, so an unthrottled /api/auth/login is an offline-speed guessing
// oracle.
type loginLimiter struct {
	mu      sync.Mutex
	buckets map[string]*loginBucket
	max     int
	window  time.Duration
	now     func() time.Time
}

type loginBucket struct {
	count int
	reset time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	if max <= 0 {
		max = 10
	}
	if window <= 0 {
		window = time.Minute
	}
	return &loginLimiter{buckets: map[string]*loginBucket{}, max: max, window: window, now: time.Now}
}

// allow records one attempt and reports whether it may proceed, plus how long
// the caller should wait when it may not.
func (l *loginLimiter) allow(key string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil || now.After(b.reset) {
		b = &loginBucket{reset: now.Add(l.window)}
		l.buckets[key] = b
	}
	if b.count >= l.max {
		return false, b.reset.Sub(now)
	}
	b.count++
	// Hard cap on the map. Expired-only cleanup is not enough: a caller can keep
	// every bucket live for a full window (and, before the X-Forwarded-For fix,
	// mint an unbounded number of distinct keys per second). When the cap is hit,
	// evict the bucket that expires soonest — the attacker's newest bucket — so
	// legitimate throttling state survives.
	if len(l.buckets) > maxLoginBuckets {
		l.evictSoonestLocked(now)
	}
	return true, 0
}

// maxLoginBuckets bounds the throttle map. Each entry is ~64 bytes, so this is a
// few hundred KB worst case.
const maxLoginBuckets = 8192

// evictSoonestLocked drops expired buckets, and if that is not enough, the
// soonest-expiring ones, until the map is back under the cap. Caller holds mu.
func (l *loginLimiter) evictSoonestLocked(now time.Time) {
	for k, v := range l.buckets {
		if now.After(v.reset) {
			delete(l.buckets, k)
		}
	}
	// Evict the bucket that expires LAST, i.e. the newest one. `reset` is
	// createdAt+window, so the earliest reset belongs to the oldest bucket — and
	// the oldest bucket is the one that has already reached max and is doing the
	// throttling. Dropping it (as the previous smallest-reset scan did) cleared
	// the attacker's own saturated counter, the opposite of the intent above.
	for len(l.buckets) > maxLoginBuckets {
		var victim string
		var victimReset time.Time
		first := true
		for k, v := range l.buckets {
			if first || v.reset.After(victimReset) {
				victim, victimReset, first = k, v.reset, false
			}
		}
		if first {
			return
		}
		delete(l.buckets, victim)
	}
}

// reset clears a bucket after a successful login so the operator is not locked
// out by their own earlier typos.
func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.buckets, key)
	l.mu.Unlock()
}

// loginClientKey identifies the client for throttling. RemoteAddr alone is wrong
// behind the documented nginx deployment (every request then arrives from
// 127.0.0.1, so one attacker can fill the single bucket and lock the operator
// out), and equally wrong under Docker's port mapping. The proxy header is only
// trusted when the connection itself comes from loopback — i.e. from a proxy on
// the same host — so a remote client cannot spoof it.
func loginClientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if fwd := forwardedClientIP(r); fwd != "" {
			return fwd
		}
	}
	return host
}

// forwardedClientIP returns the address our own proxy wrote into
// X-Forwarded-For.
//
// nginx's documented `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`
// APPENDS the peer it saw to whatever the client sent:
//
//	client sends:   X-Forwarded-For: 127.0.0.1
//	nginx forwards: X-Forwarded-For: 127.0.0.1, 203.0.113.7
//
// Everything left of the last hop is client-controlled. Reading the left-most
// entry (as this used to) let any caller claim to be 127.0.0.1, which skipped the
// first-run setup token entirely and minted a fresh throttle bucket per request.
// The right-most entry is the one our proxy appended, so that is the one used.
//
// Deployments should additionally overwrite rather than append
// (`proxy_set_header X-Forwarded-For $remote_addr`), which makes the header
// single-valued and immune to this class of confusion; see README.
func forwardedClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Walk from the right: only the nearest proxy's entry is trustworthy.
		for i := len(parts) - 1; i >= 0; i-- {
			v := strings.TrimSpace(parts[i])
			if v == "" {
				continue
			}
			if ip := net.ParseIP(v); ip != nil {
				return ip.String()
			}
			// Right-most hop is not an IP: the header is malformed. Stop here
			// rather than fall back to a client-controlled entry further left.
			return ""
		}
	}
	// X-Real-IP is deliberately NOT consulted. It is a second, independent header
	// that a proxy may or may not overwrite, so trusting it after an absent or
	// malformed X-Forwarded-For let any client choose its own throttle bucket (and
	// its own first-run loopback status). Deployments must set X-Forwarded-For.
	return ""
}

func (l *loginLimiter) reject(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Round(time.Second) / time.Second)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeErr(w, http.StatusTooManyRequests, "登录尝试过于频繁，请稍后再试")
}
