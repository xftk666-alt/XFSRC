package db

import (
	"testing"
)

func TestCheckTaskScopeHosts(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateTaskWithOptions("scope gate fixture", "read scope", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	as := d.Assets()
	add := func(kind, value, source string) {
		t.Helper()
		if _, err := as.AddAgentScope(task.ID, kind, value, "fixture", source); err != nil {
			t.Fatalf("add scope %s=%s: %v", kind, value, err)
		}
	}
	add("root_domain", "example.com", "manual")
	add("cidr", "10.0.0.0/24", "goals")
	// These must never authorize: an agent widening its own boundary, and an
	// auto-added discovered asset.
	add("root_domain", "evil.example", "agent")
	add("root_domain", "auto.example", "auto")

	blocked, err := d.CheckTaskScopeHosts(task.ID, []string{
		"api.example.com", // manual root domain covers subdomains
		"10.0.0.7",        // goals cidr covers the address
		"evil.example",    // agent-written: not trusted
		"auto.example",    // auto-written: not trusted
		"out.example.net", // never registered
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"evil.example": true, "auto.example": true, "out.example.net": true}
	if len(blocked) != len(want) {
		t.Fatalf("blocked=%v, want %v", blocked, want)
	}
	for _, h := range blocked {
		if !want[h] {
			t.Fatalf("unexpected block %q (all: %v)", h, blocked)
		}
	}
}

func TestCheckTaskScopeHostsFailClosed(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateTaskWithOptions("scope gate empty", "no scope", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	blocked, err := d.CheckTaskScopeHosts(task.ID, []string{"example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 1 {
		t.Fatalf("empty scope must fail closed, blocked=%v", blocked)
	}
}
