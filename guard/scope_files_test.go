package guard

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

func bashInput(cmd string) []byte {
	b, _ := json.Marshal(map[string]string{"command": cmd})
	return b
}

func TestFileHosts(t *testing.T) {
	dir := t.TempDir()
	ctx := intercept.WithReviewContext(context.Background(), dir, intercept.ReviewBackground{})

	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("targets.txt", "https://api.acme.com/v1\n10.0.0.5\n# comment\nacme.com:8443\n")
	write("wordlist.txt", "/admin\n/index.php\nlogin\napi\n")
	write("empty.txt", "")

	cases := []struct {
		name    string
		cmd     string
		want    []string
		blocked bool
	}{
		{"cat pipe", "cat targets.txt | httpx -silent", []string{"api.acme.com", "10.0.0.5", "acme.com"}, false},
		{"nuclei -l", "nuclei -l targets.txt -silent", []string{"api.acme.com", "10.0.0.5", "acme.com"}, false},
		{"httpx -l", "bash proxy_exec.sh httpx -l targets.txt -silent", []string{"api.acme.com", "10.0.0.5", "acme.com"}, false},
		{"stdin redirect", "httpx -silent < targets.txt", []string{"api.acme.com", "10.0.0.5", "acme.com"}, false},
		{"nmap -iL", "nmap -iL targets.txt -p 443", []string{"api.acme.com", "10.0.0.5", "acme.com"}, false},
		{"wordlist is not targets", "ffuf -u https://acme.com/FUZZ -w wordlist.txt", nil, false},
		{"empty list", "httpx -l empty.txt", nil, false},
		{"missing file fails closed", "nuclei -l missing.txt", nil, true},
		{"relative without dir fails closed", "nuclei -l targets.txt", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			useCtx := ctx
			if c.name == "relative without dir fails closed" {
				useCtx = context.Background()
			}
			got, reason := FileHosts(useCtx, "Bash", bashInput(c.cmd))
			if c.blocked {
				if reason == "" {
					t.Fatalf("expected block, got hosts=%v", got)
				}
				return
			}
			if reason != "" {
				t.Fatalf("unexpected block: %s", reason)
			}
			if len(got) != len(c.want) {
				t.Fatalf("hosts=%v want %v", got, c.want)
			}
			set := map[string]bool{}
			for _, h := range got {
				set[h] = true
			}
			for _, w := range c.want {
				if !set[w] {
					t.Fatalf("hosts=%v missing %q", got, w)
				}
			}
		})
	}
}

func TestFileHostsIgnoresNonShellTools(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "targets.txt"), []byte("acme.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := intercept.WithReviewContext(context.Background(), dir, intercept.ReviewBackground{})
	// WebFetch has no shell command: nothing to scan, no block.
	if hosts, reason := FileHosts(ctx, "WebFetch", []byte(`{"url":"https://acme.com"}`)); len(hosts) != 0 || reason != "" {
		t.Fatalf("unexpected: %v %q", hosts, reason)
	}
}
