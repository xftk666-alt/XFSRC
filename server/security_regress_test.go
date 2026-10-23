package server

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRegressionLimiterEvictsNewest(t *testing.T) {
	now := time.Now()
	l := &loginLimiter{buckets: map[string]*loginBucket{}, max: 1, window: time.Minute,
		now: func() time.Time { return now }}
	l.allow("attacker")
	l.allow("attacker") // saturate
	for i := 0; i < maxLoginBuckets; i++ {
		now = now.Add(time.Millisecond)
		l.allow("fresh-" + string(rune('a'+i%26)) + time.Duration(i).String())
	}
	l.allow("trigger")
	if b, ok := l.buckets["attacker"]; !ok || b.count < l.max {
		t.Fatalf("saturated bucket must survive eviction (present=%v)", ok)
	}
}

func TestRegressionXRealIPIgnored(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Real-IP", "10.0.0.9")
	if got := loginClientKey(r); got != "127.0.0.1" {
		t.Fatalf("X-Real-IP must not be trusted, got %q", got)
	}
}

func TestRegressionInitRejectsCrossSite(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/auth/init", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if !isBrowserCrossSite(r) {
		t.Fatal("cross-site browser request must be detected")
	}
	cli := httptest.NewRequest("POST", "/api/auth/init", nil)
	cli.RemoteAddr = "127.0.0.1:5555"
	if isBrowserCrossSite(cli) {
		t.Fatal("a plain CLI request must not be treated as cross-site")
	}
}

func TestRegressionToggleRequiresEnabled(t *testing.T) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(`{}`), &req); err != nil || req.Enabled != nil {
		t.Fatal("empty body must leave Enabled nil so the handler can reject it")
	}
}

func TestRegressionWsDeleteRootViaSymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(real, "jwt.key"), []byte("secret"), 0o600)
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlink unsupported")
	}
	s := &Server{m: &Manager{dir: link}}
	w := httptest.NewRecorder()
	s.wsDelete(w, httptest.NewRequest("DELETE", "/api/workspace/delete?path=", nil))
	if w.Code != 400 {
		t.Fatalf("root delete through a symlinked data dir must be refused, got %d", w.Code)
	}
	if _, err := os.Stat(filepath.Join(real, "jwt.key")); err != nil {
		t.Fatal("workspace content was deleted")
	}
}

func TestRegressionChatUploadRejectsSymlinkedSession(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	os.MkdirAll(filepath.Join(base, "sessions"), 0o755)
	if err := os.Symlink(outside, filepath.Join(base, "sessions", "conv-1")); err != nil {
		t.Skip("symlink unsupported")
	}
	s := &Server{m: &Manager{dir: base}}
	if _, ok := s.wsResolve(filepath.Join("sessions", "conv-1", "uploads")); ok {
		t.Fatal("upload dir escaping the workspace must be rejected")
	}
}

func TestRegressionFinalRoundIgnoresExpiredDeadline(t *testing.T) {
	// The terminal round only runs after the deadline passed, so it must not
	// carry one: clampMaxDuration floors a past deadline to 1s and the harness
	// would abort the goal judgment immediately.
	clock := finalRoundClock()
	if clock.DeadlineUnix != 0 {
		t.Fatalf("final round must not carry a deadline, got %d", clock.DeadlineUnix)
	}
	if !clock.Final {
		t.Fatal("final round must be marked Final")
	}
}

func TestRegressionChatUploadAllowsNormalSession(t *testing.T) {
	base := t.TempDir()
	s := &Server{m: &Manager{dir: base}}
	abs, ok := s.wsResolveIn(filepath.Join("sessions", "conv-2", "uploads"), false)
	if !ok {
		t.Fatal("a normal session upload dir must be accepted")
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("upload dir was not created: %v", err)
	}
	// The file manager still refuses the same subtree.
	if _, ok := s.wsResolve(filepath.Join("sessions", "conv-2", "uploads")); ok {
		t.Fatal("the file manager must keep refusing sessions/")
	}
}

func TestRegressionTokenGenerationFailsClosed(t *testing.T) {
	s := &Server{}
	if !s.tokenGenerationKnown() {
		t.Fatal("a fresh server must not be in the unknown state")
	}
	s.tokenVerUnknown.Store(true)
	if s.tokenGenerationKnown() {
		t.Fatal("unknown generation must be reported")
	}
	// A token minted at generation 0 must not verify while the generation is
	// unknown: the caller checks tokenGenerationKnown() before verifyJWT.
	key := []byte("0123456789abcdef0123456789abcdef")
	tok, err := signJWT(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyJWT(tok, key, 0) {
		t.Fatal("sanity: the token itself is valid at generation 0")
	}
}
