package server

import (
	"strings"
	"testing"
)

// Routing through the MITM is a safety decision, not an observability one.
// These tests pin that the authorization gate decides it — turning recording off
// must not hand agents the raw egress proxy, because that bypasses the gate
// entirely (the exact hole that let a compiled binary reach any host).
func TestProxyRoutingFollowsGateNotCapture(t *testing.T) {
	dir := t.TempDir()
	m, err := NewManager(dir, "127.0.0.1:18795")
	if err != nil {
		t.Skipf("manager unavailable (%v)", err)
	}
	// This test flips a global setting, so it must put it back. Defers run LIFO:
	// Close is registered first, the restore second, so the restore runs while the
	// pool is still open. (t.Cleanup would run after every defer, i.e. against a
	// closed pool — the write then fails silently and every later test in the
	// package inherits a disabled gate.)
	defer m.Close()
	defer func() {
		if err := m.pg.SetBool(settingScopeGateEnabled, true); err != nil {
			t.Errorf("restore scope_gate_enabled: %v", err)
		}
	}()
	if m.traffic == nil {
		t.Skip("traffic proxy not started")
	}

	// Default: capture off, gate on (the shipped default).
	if m.TrafficEnabled() {
		t.Fatal("capture should default to off")
	}
	if !m.scopeGateOn() {
		t.Fatal("scope gate should default to on")
	}
	if got, want := m.ProxyAddr(), m.traffic.ProxyAddr(); got != want {
		t.Fatalf("gate on + capture off: agents must route through the MITM\n got %q\nwant %q", got, want)
	}
	if m.ProxyCACert() == "" {
		t.Fatal("gate on + capture off: the MITM CA must be advertised, or every HTTPS request fails")
	}

	// Explicitly off: the gate cannot enforce what it does not see, so routing
	// falls back to the configured global proxy (empty here = direct).
	if err := m.pg.SetBool(settingScopeGateEnabled, false); err != nil {
		t.Fatal(err)
	}
	if got := m.ProxyAddr(); strings.Contains(got, "18795") || got != m.globalProxy {
		t.Fatalf("gate off: want the global proxy (%q), got %q", m.globalProxy, got)
	}
	if got := m.ProxyCACert(); got != "" {
		t.Fatalf("gate off + capture off: no MITM in the path, so no CA; got %q", got)
	}

	// Capture on always routes through the MITM, gate or not.
	if err := m.SetTrafficEnabled(true); err != nil {
		t.Fatal(err)
	}
	if got, want := m.ProxyAddr(), m.traffic.ProxyAddr(); got != want {
		t.Fatalf("capture on: want MITM %q, got %q", want, got)
	}
}
