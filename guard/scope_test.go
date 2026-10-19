package guard

import (
	"context"
	"encoding/json"
	"testing"
)

func TestExtractHosts(t *testing.T) {
	cases := []struct {
		name  string
		tool  string
		input string
		want  []string
	}{
		{
			name:  "curl url",
			tool:  "Bash",
			input: `{"command":"curl -s https://api.example.com/v1/users?id=1"}`,
			want:  []string{"api.example.com"},
		},
		{
			name:  "nmap bare ip and host",
			tool:  "Bash",
			input: `{"command":"nmap -Pn -p 443 10.0.0.5 scan.example.com"}`,
			want:  []string{"10.0.0.5", "scan.example.com"},
		},
		{
			name:  "wordlist and script paths ignored",
			tool:  "Bash",
			input: `{"command":"ffuf -u https://t.example.com/FUZZ -w /usr/share/wordlists/common.txt -o out.json"}`,
			want:  []string{"t.example.com"},
		},
		{
			name:  "webfetch url",
			tool:  "WebFetch",
			input: `{"url":"http://10.1.2.3:8080/x"}`,
			want:  []string{"10.1.2.3"},
		},
		{
			name:  "jwt is not a hostname",
			tool:  "Bash",
			input: `{"command":"python3 jwt_decode.py 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc'"}`,
			want:  nil,
		},
		{
			name:  "wordlist path and output file ignored",
			tool:  "Bash",
			input: `{"command":"ffuf -u https://t.example.com/FUZZ -w /usr/local/share/wordlists/common.txt -o out.json"}`,
			want:  []string{"t.example.com"},
		},
		{
			name:  "custom tool string args",
			tool:  "httpx_probe",
			input: `{"targets":"a.example.com,b.example.org"}`,
			want:  []string{"a.example.com", "b.example.org"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExtractHosts(c.tool, []byte(c.input))
			if len(got) != len(c.want) {
				t.Fatalf("ExtractHosts(%s) = %v, want %v", c.input, got, c.want)
			}
			set := map[string]bool{}
			for _, h := range got {
				set[h] = true
			}
			for _, w := range c.want {
				if !set[w] {
					t.Fatalf("ExtractHosts(%s) = %v, missing %q", c.input, got, w)
				}
			}
		})
	}
}

func TestScopeGateBlocksBeforeIntercept(t *testing.T) {
	g := New()
	g.SetScopeCheck(func(_ context.Context, tool string, input []byte) ([]string, string) {
		var blocked []string
		for _, h := range ExtractHosts(tool, input) {
			if h != "in.example.com" {
				blocked = append(blocked, h)
			}
		}
		if len(blocked) == 0 {
			return nil, ""
		}
		return blocked, "out of scope"
	})

	call := func(cmd string) bool {
		input, _ := json.Marshal(map[string]string{"command": cmd})
		blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
		if blocked && msg == "" {
			t.Fatal("block must carry a message")
		}
		return blocked
	}
	if call(`curl https://in.example.com/`) {
		t.Fatal("in-scope target was blocked")
	}
	if !call(`curl https://out.example.com/`) {
		t.Fatal("out-of-scope target was allowed")
	}
	if !call(`curl https://in.example.com/ https://evil.example.net/`) {
		t.Fatal("a single out-of-scope target must block the whole call")
	}
}

func TestRuleSubjectIgnoresWriteContent(t *testing.T) {
	write := []byte(`{"file_path":"/app/data/tasks/1/report.md","content":"PoC: rm -rf / and DROP TABLE users"}`)
	subject := string(ruleSubject("Write", write))
	if subject != `{"file_path":"/app/data/tasks/1/report.md"}` {
		t.Fatalf("Write rules must only see file_path, got %s", subject)
	}
	// Bash still exposes the command that will actually run.
	bash := []byte(`{"command":"rm -rf /tmp/x","description":"cleanup"}`)
	if got := string(ruleSubject("Bash", bash)); got != `{"command":"rm -rf /tmp/x"}` {
		t.Fatalf("Bash rules must see the command, got %s", got)
	}
}

func TestReasonOnlyVerdictBlocks(t *testing.T) {
	g := New()
	g.SetScopeCheck(func(context.Context, string, []byte) ([]string, string) {
		return nil, "目标列表无法读取，已按 fail-closed 阻止"
	})
	input, _ := json.Marshal(map[string]string{"command": "nuclei -l missing.txt"})
	blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
	if !blocked || msg == "" {
		t.Fatalf("a reason-only verdict must block, blocked=%v msg=%q", blocked, msg)
	}
}
