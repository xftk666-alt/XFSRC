package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func authTestServer(t *testing.T) *Server {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	dir := t.TempDir()
	s := New(t.Context(), m, dir, dir, dir)
	// Each test starts from a claimable instance.
	if _, err := m.pg.Exec(`DELETE FROM settings WHERE key IN ($1,$2,$3)`, authPassKey, authTokenVersionKey, authSetupTokenKey); err != nil {
		t.Fatal(err)
	}
	s.tokenVer.Store(0)
	s.ensureSetupToken(dir)
	return s
}

func authCall(s *Server, method, path, body, remote string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	if remote != "" {
		req.RemoteAddr = remote
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// A fresh instance reachable from the network must not be claimable by whoever
// gets there first: /api/auth/init requires the token printed in the server log.
func TestAuthInitRequiresSetupTokenRemotely(t *testing.T) {
	s := authTestServer(t)

	// Remote caller without a token → refused.
	rec := authCall(s, http.MethodPost, "/api/auth/init", `{"password":"Remote-Pass-1"}`, "203.0.113.7:5555", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("remote init without setup token: %d %s", rec.Code, rec.Body)
	}
	// Wrong token → still refused.
	rec = authCall(s, http.MethodPost, "/api/auth/init", `{"password":"Remote-Pass-1","setup_token":"nope"}`, "203.0.113.7:5555", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("remote init with wrong token: %d %s", rec.Code, rec.Body)
	}
	// The real token works.
	tok, ok, err := s.m.pg.GetSetting(authSetupTokenKey)
	if err != nil || !ok || tok == "" {
		t.Fatalf("setup token not generated: %v %v", ok, err)
	}
	rec = authCall(s, http.MethodPost, "/api/auth/init", `{"password":"Remote-Pass-1","setup_token":"`+tok+`"}`, "203.0.113.7:5555", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("remote init with valid token: %d %s", rec.Code, rec.Body)
	}
	// A second attempt cannot re-claim the instance.
	rec = authCall(s, http.MethodPost, "/api/auth/init", `{"password":"Attacker-Pass-1","setup_token":"`+tok+`"}`, "203.0.113.7:5555", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("second init must be refused: %d %s", rec.Code, rec.Body)
	}
	// The setup token is single-use.
	if v, _, _ := s.m.pg.GetSetting(authSetupTokenKey); v != "" {
		t.Fatal("setup token was not consumed")
	}
}

// Behind a same-host reverse proxy every request looks local; the forwarded
// client address must still be treated as remote, or the setup-token guard is
// bypassed for every internet caller.
func TestAuthInitTreatsProxiedRemoteClientAsRemote(t *testing.T) {
	s := authTestServer(t)
	rec := authCall(s, http.MethodPost, "/api/auth/init", `{"password":"Proxied-Pass-1"}`, "127.0.0.1:5555",
		map[string]string{"X-Forwarded-For": "203.0.113.9"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("proxied remote init without setup token: %d %s", rec.Code, rec.Body)
	}
	// A loopback forwarded address (another local process) stays exempt.
	rec = authCall(s, http.MethodPost, "/api/auth/init", `{"password":"Proxied-Pass-1"}`, "127.0.0.1:5555",
		map[string]string{"X-Forwarded-For": "127.0.0.1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback forwarded init: %d %s", rec.Code, rec.Body)
	}
}

// Local access keeps the documented flow working without a token.
func TestAuthInitAllowsLoopbackWithoutToken(t *testing.T) {
	s := authTestServer(t)
	rec := authCall(s, http.MethodPost, "/api/auth/init", `{"password":"Local-Pass-1"}`, "127.0.0.1:5555", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback init: %d %s", rec.Code, rec.Body)
	}
}

func TestAuthStatusReportsSetupTokenRequirement(t *testing.T) {
	s := authTestServer(t)
	local := authCall(s, http.MethodGet, "/api/auth/status", "", "127.0.0.1:5555", nil)
	var localBody struct {
		Initialized        bool `json:"initialized"`
		RequiresSetupToken bool `json:"requires_setup_token"`
	}
	if err := json.Unmarshal(local.Body.Bytes(), &localBody); err != nil {
		t.Fatal(err)
	}
	if localBody.Initialized || localBody.RequiresSetupToken {
		t.Fatalf("local status = %+v", localBody)
	}
	remote := authCall(s, http.MethodGet, "/api/auth/status", "", "203.0.113.7:5555", nil)
	var remoteBody struct {
		RequiresSetupToken bool `json:"requires_setup_token"`
	}
	if err := json.Unmarshal(remote.Body.Bytes(), &remoteBody); err != nil {
		t.Fatal(err)
	}
	if !remoteBody.RequiresSetupToken {
		t.Fatal("remote caller was not told a setup token is required")
	}
}

// The session cookie must be unreadable by page scripts, and the token must not
// be accepted from the query string outside SSE.
func TestAuthCookieAndTokenTransport(t *testing.T) {
	s := authTestServer(t)
	rec := authCall(s, http.MethodPost, "/api/auth/init", `{"password":"Cookie-Pass-1"}`, "127.0.0.1:5555", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("init: %d %s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != authCookieName {
		t.Fatalf("cookies = %+v", cookies)
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Error("session cookie is readable by JavaScript (HttpOnly missing)")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", c.SameSite)
	}

	token := c.Value
	ok := authCall(s, http.MethodGet, "/api/tasks", "", "127.0.0.1:5555", map[string]string{"Authorization": "Bearer " + token})
	if ok.Code != http.StatusOK {
		t.Fatalf("header auth: %d", ok.Code)
	}
	bad := authCall(s, http.MethodGet, "/api/tasks?token="+token, "", "127.0.0.1:5555", nil)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("query token on a normal API must be rejected, got %d", bad.Code)
	}
	// SSE keeps the query-string fallback because EventSource cannot set headers;
	// assert on token extraction rather than opening a stream that never ends.
	sseReq := httptest.NewRequest(http.MethodGet, "/api/exploration/activity/stream?token="+token, nil)
	if got := extractToken(sseReq); got != token {
		t.Fatalf("SSE query token not accepted: %q", got)
	}
	plainReq := httptest.NewRequest(http.MethodGet, "/api/tasks?token="+token, nil)
	if got := extractToken(plainReq); got != "" {
		t.Fatalf("query token accepted outside SSE: %q", got)
	}
}

// Logout and password change must invalidate tokens already in the wild.
func TestAuthLogoutAndPasswordChangeRevokeTokens(t *testing.T) {
	s := authTestServer(t)
	rec := authCall(s, http.MethodPost, "/api/auth/init", `{"password":"Revoke-Pass-1"}`, "127.0.0.1:5555", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("init: %d %s", rec.Code, rec.Body)
	}
	old := rec.Result().Cookies()[0].Value

	if code := authCall(s, http.MethodPost, "/api/auth/logout", "", "127.0.0.1:5555",
		map[string]string{"Authorization": "Bearer " + old}).Code; code != http.StatusOK {
		t.Fatalf("logout: %d", code)
	}
	if code := authCall(s, http.MethodGet, "/api/tasks", "", "127.0.0.1:5555",
		map[string]string{"Authorization": "Bearer " + old}).Code; code != http.StatusUnauthorized {
		t.Fatalf("token survived logout: %d", code)
	}

	// Log back in, then change the password: the pre-change token dies.
	login := authCall(s, http.MethodPost, "/api/auth/login", `{"username":"XFSRC","password":"Revoke-Pass-1"}`,
		"127.0.0.1:5555", nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login: %d %s", login.Code, login.Body)
	}
	pre := login.Result().Cookies()[0].Value
	chg := authCall(s, http.MethodPost, "/api/auth/change-password",
		`{"old_password":"Revoke-Pass-1","new_password":"Revoke-Pass-2"}`, "127.0.0.1:5555",
		map[string]string{"Authorization": "Bearer " + pre})
	if chg.Code != http.StatusOK {
		t.Fatalf("change password: %d %s", chg.Code, chg.Body)
	}
	if code := authCall(s, http.MethodGet, "/api/tasks", "", "127.0.0.1:5555",
		map[string]string{"Authorization": "Bearer " + pre}).Code; code != http.StatusUnauthorized {
		t.Fatalf("token survived a password change: %d", code)
	}
	// The response carries a fresh token so the operator is not logged out.
	if fresh := chg.Result().Cookies(); len(fresh) == 0 || fresh[0].Value == "" {
		t.Fatal("password change did not reissue a session cookie")
	}
}

// Request bodies are capped, and the cap is reported as 413 rather than a
// confusing decode error.
func TestRequestBodyLimit(t *testing.T) {
	s := authTestServer(t)
	big := strings.Repeat("a", int(maxJSONBodyBytes)+1024)
	rec := authCall(s, http.MethodPost, "/api/auth/init", `{"password":"`+big+`"}`, "127.0.0.1:5555", nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d, want 413", rec.Code)
	}
}

// The login limiter must key on the real client behind a local reverse proxy,
// otherwise one attacker fills the single bucket and locks the operator out.
func TestLoginLimiterUsesForwardedClientIP(t *testing.T) {
	s := authTestServer(t)
	if rec := authCall(s, http.MethodPost, "/api/auth/init", `{"password":"Limit-Pass-1"}`, "127.0.0.1:5555", nil); rec.Code != http.StatusOK {
		t.Fatalf("init: %d %s", rec.Code, rec.Body)
	}
	body := `{"username":"XFSRC","password":"wrong"}`
	for i := range 11 {
		code := authCall(s, http.MethodPost, "/api/auth/login", body, "127.0.0.1:5555",
			map[string]string{"X-Forwarded-For": "203.0.113." + strconv.Itoa(i+1)}).Code
		if code == http.StatusTooManyRequests {
			t.Fatalf("distinct forwarded clients shared a bucket at attempt %d", i+1)
		}
	}
	throttled := false
	for range 12 {
		if authCall(s, http.MethodPost, "/api/auth/login", body, "127.0.0.1:5555",
			map[string]string{"X-Forwarded-For": "198.51.100.9"}).Code == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Fatal("repeated attempts from one forwarded client were never throttled")
	}
}
