package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newWorkspaceServer builds the minimum Server needed by wsResolve: the work dir.
func newWorkspaceServer(t *testing.T) (*Server, string) {
	t.Helper()
	root := t.TempDir()
	return &Server{m: &Manager{dir: root}}, root
}

func TestWsResolveConfinesAndDeniesSecrets(t *testing.T) {
	s, root := newWorkspaceServer(t)

	if _, ok := s.wsResolve("tasks/1/report.md"); !ok {
		t.Fatal("ordinary workspace path rejected")
	}
	// ".." is neutralised by rooting at the workspace, not rejected outright: the
	// result must stay inside the root.
	got, ok := s.wsResolve("../../etc/passwd")
	if !ok {
		t.Fatal("rooted traversal should resolve inside the workspace")
	}
	if !strings.HasPrefix(got, root+string(os.PathSeparator)) {
		t.Fatalf("traversal escaped the workspace: %s", got)
	}
	for _, denied := range []string{"evidence/pack.json", "traffic/x", "transcripts/a.json", "sessions/s", "jwt.key", "_ca/k"} {
		if _, ok := s.wsResolve(denied); ok {
			t.Fatalf("sensitive path %q was resolvable", denied)
		}
	}
	// A new file below the root is allowed (nothing to resolve yet).
	if _, ok := s.wsResolve("tasks/2/new/artifact.txt"); !ok {
		t.Fatal("new file inside the workspace rejected")
	}
}

// A symlink inside the workspace must not rename a denied subtree into an
// allowed-looking path, and must not point outside the root.
func TestWsResolveRejectsSymlinkEscape(t *testing.T) {
	s, root := newWorkspaceServer(t)
	if err := os.MkdirAll(filepath.Join(root, "traffic"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "traffic", "body.bin"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// ln -s traffic data/x  →  read?path=x/body.bin would resolve into traffic/.
	if err := os.Symlink("traffic", filepath.Join(root, "x")); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.wsResolve("x/body.bin"); ok {
		t.Fatal("symlink let a denied subtree be read through an allowed path")
	}
	// A link pointing outside the workspace must be refused.
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "out")); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.wsResolve("out/secret.txt"); ok {
		t.Fatal("symlink pointing outside the root was accepted")
	}
}

// A dangling symlink has no resolvable target; writing through it would create a
// file at the (attacker-chosen) destination outside the workspace.
func TestWsResolveRejectsDanglingSymlink(t *testing.T) {
	s, root := newWorkspaceServer(t)
	victim := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.Symlink(victim, filepath.Join(root, "y")); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.wsResolve("y"); ok {
		t.Fatal("dangling symlink accepted (write would escape the workspace)")
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatal("test fixture unexpectedly created the target")
	}
}
