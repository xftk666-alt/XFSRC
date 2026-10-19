package server

import (
	"net"
	"net/http"
	"strconv"
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
	// Opportunistic cleanup: keep the map from growing with spoofed sources.
	if len(l.buckets) > 4096 {
		for k, v := range l.buckets {
			if now.After(v.reset) {
				delete(l.buckets, k)
			}
		}
	}
	return true, 0
}

// reset clears a bucket after a successful login so the operator is not locked
// out by their own earlier typos.
func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.buckets, key)
	l.mu.Unlock()
}

func loginClientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (l *loginLimiter) reject(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Round(time.Second) / time.Second)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeErr(w, http.StatusTooManyRequests, "登录尝试过于频繁，请稍后再试")
}
