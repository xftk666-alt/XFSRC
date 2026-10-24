package traffic

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The recording proxy is the only enforcement point a compiled binary or an
// obfuscated command line cannot step around: a request that reaches it still
// has to name a host. These tests pin the refusal, and pin that a refused
// request never reaches the target.

func startGatedProxy(t *testing.T, allow func(string) bool) (*Traffic, *http.Client) {
	t.Helper()
	tr, err := Open(t.TempDir(), "127.0.0.1:18789")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	tr.SetEgressGate(allow)
	go func() { _ = tr.Start() }()
	time.Sleep(200 * time.Millisecond)
	proxyURL, err := url.Parse(tr.ProxyAddr())
	if err != nil {
		t.Fatal(err)
	}
	return tr, &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
}

func TestEgressGateRefusesUnauthorizedHost(t *testing.T) {
	_, client := startGatedProxy(t, func(host string) bool { return host == "allowed.example" })

	resp, err := client.Get("http://denied.example/x")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "授权范围") {
		t.Errorf("refusal should explain why; got %q", body)
	}
}

// A refused host must never be dialed. The target is a live server that records
// hits, so a regression that forwards before checking shows up here.
func TestEgressGateDoesNotContactTarget(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte("reached"))
	}))
	defer target.Close()
	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}

	// Allow everything except the target: the gate must stop it.
	_, client := startGatedProxy(t, func(host string) bool { return false })
	resp, err := client.Get(target.URL + "/x")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if hits != 0 {
		t.Fatalf("target was contacted %d time(s) despite the refusal", hits)
	}
	_ = targetURL
}

// A nil gate keeps standalone proxy use working.
func TestEgressGateAbsentAllowsEverything(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	tr, err := Open(t.TempDir(), "127.0.0.1:18790")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	go func() { _ = tr.Start() }()
	time.Sleep(200 * time.Millisecond)
	proxyURL, _ := url.Parse(tr.ProxyAddr())
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get(target.URL + "/x")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
