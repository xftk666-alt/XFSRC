package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestScopeGateForTask(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	task, err := m.pg.CreateTaskWithOptions("scope gate", "smoke", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(task.ID) })

	check := scopeGateFor(m.pg, task.ID)
	bash := func(cmd string) ([]string, string) {
		return check(context.Background(), "Bash", []byte(`{"command":"`+cmd+`"}`))
	}

	// No trusted scope: fail closed.
	if blocked, _ := bash("curl https://example.com"); len(blocked) == 0 {
		t.Fatal("empty scope must block")
	}
	// Agent-written scope does not authorize.
	if _, err := m.assets.AddAgentScope(task.ID, "root_domain", "example.com", "agent", "agent"); err != nil {
		t.Fatal(err)
	}
	if blocked, _ := bash("curl https://example.com"); len(blocked) == 0 {
		t.Fatal("agent-written scope must not authorize")
	}
	// Operator-confirmed scope authorizes the host and its subdomains.
	if _, err := m.assets.AddAgentScope(task.ID, "root_domain", "example.com", "operator", "manual"); err != nil {
		t.Fatal(err)
	}
	if blocked, reason := bash("curl https://api.example.com/v1"); len(blocked) != 0 {
		t.Fatalf("manual scope must authorize subdomain, blocked=%v reason=%s", blocked, reason)
	}
	// A different host is still blocked, and one bad host blocks the whole call.
	blocked, reason := bash("curl https://api.example.com https://evil.example.net")
	if len(blocked) != 1 || blocked[0] != "evil.example.net" || reason == "" {
		t.Fatalf("mixed call blocked=%v reason=%q", blocked, reason)
	}

	// Targets carried in a file must be checked too: a target list is the
	// easiest way to bypass argument-only extraction.
	dir := t.TempDir()
	inScope := filepath.Join(dir, "in.txt")
	outScope := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(inScope, []byte("api.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outScope, []byte("evil.example.net\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileCheck := func(cmd string) ([]string, string) {
		return check(context.Background(), "Bash", []byte(`{"command":"`+cmd+`"}`))
	}
	if b, r := fileCheck("nuclei -l " + inScope); len(b) != 0 {
		t.Fatalf("in-scope target file blocked: %v %s", b, r)
	}
	if b, r := fileCheck("nuclei -l " + outScope); len(b) == 0 || r == "" {
		t.Fatalf("out-of-scope target file allowed: %v %q", b, r)
	}
	if b, r := fileCheck("cat " + outScope + " | httpx -silent"); len(b) == 0 || r == "" {
		t.Fatalf("out-of-scope piped target file allowed: %v %q", b, r)
	}
	// An unreadable list yields no hosts but a fail-closed reason; the guard
	// blocks on either signal (see guard.TestReasonOnlyVerdictBlocks).
	if _, r := fileCheck("nuclei -l " + filepath.Join(dir, "missing.txt")); r == "" {
		t.Fatal("unreadable target list must fail closed")
	}
}
