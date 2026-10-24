package guard

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

// The authorization gate is only as good as the targets it can see. These cases
// pin the shapes that used to carry a target invisibly: an inline program passed
// with -c/-e, and a compiled binary whose body cannot be read.
//
// Each case states the verdict the gate must reach, not the mechanism, so the
// tests survive a rewrite of the extractor.

func reviewCtx(dir string) context.Context {
	return intercept.WithReviewContext(context.Background(), dir, intercept.ReviewBackground{})
}

// Inline interpreter programs must expose their targets. Before this was fixed,
// `python3 -c "…urlopen('http://x')"` captured no script at all, so the gate saw
// a call with no targets and allowed it.
func TestInlineProgramTargetsAreVisible(t *testing.T) {
	ctx := reviewCtx(t.TempDir())
	cases := []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "python urlopen",
			command: `python3 -c "import urllib.request;urllib.request.urlopen('http://evil.example.com/x')"`,
			want:    "evil.example.com",
		},
		{
			name:    "node fetch",
			command: `node -e "fetch('http://evil.example.com/x')"`,
			want:    "evil.example.com",
		},
		{
			name:    "ruby net/http",
			command: `ruby -e "require 'net/http'; Net::HTTP.get(URI('http://evil.example.com'))"`,
			want:    "evil.example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hosts, reason := ScriptHosts(ctx, "Bash", bashInput(tc.command))
			if reason != "" {
				t.Fatalf("inline program was rejected instead of scanned: %s", reason)
			}
			if !containsHost(hosts, tc.want) {
				t.Fatalf("target %q not extracted from inline program; got %v", tc.want, hosts)
			}
		})
	}
}

// An inline program with no network call must not be rejected: the fix captures
// the body for scanning, and a body that names nothing must stay silent.
func TestInlineProgramWithoutTargetIsAllowed(t *testing.T) {
	ctx := reviewCtx(t.TempDir())
	for _, command := range []string{
		`python3 -c "print(1)"`,
		`node -e "console.log(1)"`,
	} {
		hosts, reason := ScriptHosts(ctx, "Bash", bashInput(command))
		if reason != "" || len(hosts) != 0 {
			t.Errorf("%s => hosts=%v reason=%q; want no targets and no block", command, hosts, reason)
		}
	}
}

// A directly executed compiled binary has unreadable targets. It used to be
// dropped from the capture entirely, which made `./recon` indistinguishable from
// a call that touches nothing.
func TestCompiledBinaryIsReportedAsOpaque(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "recon")
	// A minimal ELF header is enough: the capture only inspects the magic.
	if err := os.WriteFile(binary, append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 64)...), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := reviewCtx(dir)
	for _, command := range []string{"./recon", "./recon 10.0.0.5"} {
		opaque := OpaqueExecs(ctx, "Bash", bashInput(command))
		if len(opaque) == 0 {
			t.Fatalf("%q: compiled binary not reported as opaque", command)
		}
		if !strings.Contains(opaque[0], "recon") {
			t.Errorf("%q: opaque entry should name the binary; got %v", command, opaque)
		}
	}
}

// go run compiles and executes a package whose targets live anywhere in its
// source. The call is opaque for the same reason a prebuilt binary is.
func TestGoRunIsOpaque(t *testing.T) {
	ctx := reviewCtx(t.TempDir())
	opaque := OpaqueExecs(ctx, "Bash", bashInput("go run ./cmd/recon"))
	if len(opaque) == 0 {
		t.Fatal("go run must be reported as an opaque execution")
	}
}

// Ordinary commands must stay opaque-free, or every call would be denied.
func TestOrdinaryCommandsAreNotOpaque(t *testing.T) {
	ctx := reviewCtx(t.TempDir())
	for _, command := range []string{
		`curl http://evil.example.com`,
		`ls -la`,
		`echo hello`,
		`go build ./...`,
		`go test ./...`,
	} {
		if opaque := OpaqueExecs(ctx, "Bash", bashInput(command)); len(opaque) != 0 {
			t.Errorf("%q: want no opaque entries, got %v", command, opaque)
		}
	}
}

func containsHost(hosts []string, want string) bool {
	for _, h := range hosts {
		if h == want {
			return true
		}
	}
	return false
}

// The bypass list that motivated this hardening, re-run against the gate. Each
// entry used to reach the network with no target the gate could see.
func TestKnownBypassShapesAreClosed(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "small")
	if err := os.WriteFile(binary, append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 64)...), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := reviewCtx(dir)
	cases := []struct {
		name, command string
		wantBlocked   bool
	}{
		{"inline python", `python3 -c "import urllib.request;urllib.request.urlopen('http://evil.example.com')"`, false},
		{"inline node", `node -e "fetch('http://evil.example.com/x')"`, false},
		{"compiled binary", `./small`, true},
		{"go run", `go run ./cmd/recon`, true},
		{"stdin pipe", `cat /tmp/x.py | python3`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hosts, reason := ScriptHosts(ctx, "Bash", bashInput(tc.command))
			opaque := OpaqueExecs(ctx, "Bash", bashInput(tc.command))
			blocked := reason != "" || len(opaque) > 0
			if blocked != tc.wantBlocked {
				t.Fatalf("%s: blocked=%v want %v (hosts=%v opaque=%v reason=%q)",
					tc.name, blocked, tc.wantBlocked, hosts, opaque, reason)
			}
			if !tc.wantBlocked && len(hosts) == 0 {
				t.Fatalf("%s: must expose a target instead of being blocked", tc.name)
			}
		})
	}
}
