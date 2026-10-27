package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A private repo's releases endpoint returns 404 without auth, so the update
// client must attach the configured token.
func TestAuthTransportAddsBearer(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &http.Client{Transport: &authTransport{base: http.DefaultTransport, token: "tok123"}}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got != "Bearer tok123" {
		t.Fatalf("Authorization = %q", got)
	}
}

// The token must never be echoed back to the browser.
func TestUpdateSettingsTokenNotEchoed(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if err := m.pg.SetSetting(updateSettingsKey, `{"proxy":"","token":"secret-token"}`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.SetSetting(updateSettingsKey, "") })

	cfg, err := (&Server{m: m}).loadUpdateSettings()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "secret-token" {
		t.Fatalf("token not loaded: %q", cfg.Token)
	}
}
