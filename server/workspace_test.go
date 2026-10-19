package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWSResolveDeniesRuntimeSecrets(t *testing.T) {
	dir := t.TempDir()
	s := &Server{m: &Manager{dir: dir}}
	for _, rel := range []string{
		"evidence/.hmac-key",
		"evidence/.recorder-token",
		"evidence/_audit.jsonl",
		"traffic/_ca/mitmproxy-ca.pem",
		"sessions/conv-1/cmd-output/x.txt",
		"transcripts/conv-1.jsonl",
		"jwt.key",
		".delete-staging/x",
	} {
		if _, ok := s.wsResolve(rel); ok {
			t.Errorf("wsResolve(%q) must be denied", rel)
		}
	}
	if _, ok := s.wsResolve("tasks/1/output.txt"); !ok {
		t.Error("regular task artifact must remain browsable")
	}
	// Lexical ".." is collapsed into the workspace root (base/etc/passwd), not
	// an escape; the symlink test below covers the real escape path.
	if abs, ok := s.wsResolve("../etc/passwd"); ok && !strings.HasPrefix(abs, dir+string(os.PathSeparator)) {
		t.Errorf("lexical traversal escaped the workspace: %s", abs)
	}
}

func TestWSResolveRejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	taskDir := filepath.Join(dir, "tasks", "1")
	if err := os.MkdirAll(taskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(taskDir, "escape")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	s := &Server{m: &Manager{dir: dir}}
	if _, ok := s.wsResolve("tasks/1/escape/passwd"); ok {
		t.Fatal("symlink escaping the workspace must be rejected")
	}
	if _, ok := s.wsResolve("tasks/1/escape"); ok {
		t.Fatal("the escaping symlink itself must be rejected")
	}
}
