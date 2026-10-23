package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func gate(t *testing.T, cmd string) (hosts, files, scripts []string, fr, sr string) {
	t.Helper()
	in, _ := json.Marshal(map[string]string{"command": cmd})
	h, pr := ExtractHostsChecked("Bash", in)
	f, fr := FileHosts(context.Background(), "Bash", in)
	s, sr := ScriptHosts(context.Background(), "Bash", in)
	if pr != "" {
		fr = pr
	}
	return h, f, s, fr, sr
}

func TestRegressionGateVectors(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "targets.txt")
	os.WriteFile(list, []byte("http://out-of-scope.example/\n"), 0o644)
	urlFile := filepath.Join(dir, "url.txt")
	os.WriteFile(urlFile, []byte("http://out-of-scope.example/"), 0o644)

	cases := []struct{ name, cmd string }{
		{"wget -i", "wget -q -T 3 -i " + list + " -O /dev/null"},
		{"wget --input-file", "wget -q --input-file=" + list + " -O /dev/null"},
		{"sh -c wget -i", `sh -c "wget -q -T 3 -i ` + list + ` -O /dev/null"`},
		{"bash -c nuclei -l", `bash -c "nuclei -l ` + list + `"`},
		{"cmd subst cat", `curl -s "$(cat ` + urlFile + `)"`},
		{"cmd subst echo", `wget -q -i "$(echo ` + list + `)" -O /dev/null`},
	}
	for _, c := range cases {
		hosts, files, scripts, fr, _ := gate(t, c.cmd)
		found := len(hosts)+len(files)+len(scripts) > 0 || fr != ""
		fmt.Printf("%-22s gate sees something=%v hosts=%v file=%v\n", c.name, found, hosts, files)
		if !found {
			t.Errorf("%s: gate saw nothing, bypass still open", c.name)
		}
	}
}

func TestRegressionSingleLabelAnyTool(t *testing.T) {
	for _, cmd := range []string{
		"openssl s_client -connect juice-shop:3000",
		"redis-cli -h juice-shop",
		"socat - TCP:juice-shop:3000",
		"grpcurl juice-shop:443 list",
	} {
		hosts, _, _, _, _ := gate(t, cmd)
		fmt.Printf("%-42s hosts=%v\n", cmd, hosts)
		if len(hosts) == 0 {
			t.Errorf("%s: single-label target not extracted", cmd)
		}
	}
}

func TestRegressionNonNetworkToolsIgnored(t *testing.T) {
	in, _ := json.Marshal(map[string]string{"summary": "探测 out-of-scope.example 失败"})
	if h, r := ExtractHostsChecked("record_fact", in); len(h) != 0 || r != "" {
		t.Fatalf("record_fact must not be scanned for targets: %v %q", h, r)
	}
}

func TestRegressionUnparseableURLFailsClosed(t *testing.T) {
	_, _, _, fr, _ := gate(t, `curl http://host%2e.example/`)
	if fr == "" {
		t.Fatal("unparseable URL must produce a fail-closed reason")
	}
}

func TestRegressionUserinfoOnlyInAuthority(t *testing.T) {
	for _, line := range []string{
		"https://evil.example/redirect?to=@in-scope.example",
		"https://evil.example/path@in-scope.example",
	} {
		h, ok := parseTargetLine(line)
		if !ok || h != "evil.example" {
			t.Errorf("%s -> %q,%v want evil.example", line, h, ok)
		}
	}
}

func TestRegressionAuditOrdering(t *testing.T) {
	g := New()
	g.SetScopeCheck(func(context.Context, string, []byte) ([]string, string) {
		return []string{"evil.example"}, "目标不在本任务授权范围内"
	})
	in, _ := json.Marshal(map[string]string{"command": "curl http://evil.example/"})
	block, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", in)
	if !block {
		t.Fatal("expected block")
	}
	for _, e := range g.Audit() {
		if e.Action == "allow" {
			t.Fatalf("blocked call left an allow row: %+v", e)
		}
	}
}

func TestRegressionRedirectDestinationNotTargetList(t *testing.T) {
	in, _ := json.Marshal(map[string]string{"command": "curl -s http://allowed.example/ > out.txt; cat out.txt"})
	_, reason := FileHosts(context.Background(), "Bash", in)
	if reason != "" {
		t.Fatalf("own output file must not be read as a target list: %q", reason)
	}
}
