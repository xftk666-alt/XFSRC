package intercept

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegressionVerdictSafety(t *testing.T) {
	long := strings.Repeat("实际操作：删库；成功后的后果：数据全丢；", 200)
	denyish := []string{
		`{"decision":"deny","comment":"实际操作：执行 rm；成功后的后果：删除文件","confidence":0.95}`,
		`{"decision":"deny","comment":"实际操作：执行 rm；成功后的后果：删除文件","extra":true}`,
		`{"decision":"deny","comment":"` + long + `"}`,
		`{"decision":"ask","comment":"实际操作：执行 rm；成功后的后果：删除文件","confidence":1}`,
	}
	for _, in := range denyish {
		if got := ParseVerdict(in); got.Action == "" {
			t.Errorf("safe-direction verdict was discarded: %.80s", in)
		}
	}
	permissive := []string{
		`{"decision":"allow","comment":"实际操作：读取；成功后的后果：返回内容；命中规则：A5","extra":true}`,
		`{"decision":"allow","comment":"` + long + `"}`,
	}
	for _, in := range permissive {
		if got := ParseVerdict(in); got.Action != "" {
			t.Errorf("permissive verdict accepted on a malformed reply: %.80s", in)
		}
	}
}

// TestRegressionDefaultGatesDangerousTools pins the fail-closed default: with no
// saved allow-list every tool is inspected except the read-only exempt set.
func TestRegressionDefaultGatesDangerousTools(t *testing.T) {
	i := &Interceptor{enabledToolsAll: true, toolsLoaded: true}
	for _, name := range []string{
		"Bash", "WebFetch", "Write", "Edit",
		"delete_assets_by_host", "spawn_task", "pause_task",
		"create_custom_tool", "create_mcp", "update_mcp",
		"mcp__browser__navigate", "report_finding", "insert_assets",
	} {
		if !i.IsToolEnabled(name) {
			t.Errorf("%s must enter the intercept layer by default", name)
		}
	}
	for _, name := range []string{"record_fact", "add_intent", "list_assets", "get_task_graph"} {
		if i.IsToolEnabled(name) {
			t.Errorf("%s is read-only and must stay exempt", name)
		}
	}
}

// TestRegressionNestedScriptCapture covers targets that live one level deeper
// than the command line: a sourced file, eval's argument, and the command behind
// xargs / find -exec.
func TestRegressionNestedScriptCapture(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("b.sh", "curl -s http://deep.example/\n")
	write("evil.py", "print(1)\n")
	a := write("a.sh", "source ./b.sh\npython3 "+filepath.Join(dir, "evil.py")+"\n")

	for _, cmd := range []string{
		"sh " + a,
		"eval 'sh " + a + "'",
		"echo x | xargs sh " + a,
		"find /tmp -name x -exec sh " + a + " \\;",
	} {
		in, _ := json.Marshal(map[string]string{"command": cmd})
		scripts, status := CaptureScripts(dir, "Bash", in)
		if status != "complete" {
			t.Errorf("%s: status=%s", cmd, status)
		}
		var haveB bool
		for _, s := range scripts {
			if strings.HasSuffix(s.Path, "b.sh") {
				haveB = true
			}
		}
		if !haveB {
			t.Errorf("%s: sourced file b.sh was not captured", cmd)
		}
	}
}

// TestRegressionCoverageListingIncludesSDKTools: the settings UI must show the
// SDK tools too — they have no row in the tools table but are gated.
func TestRegressionCoverageListingIncludesSDKTools(t *testing.T) {
	i := &Interceptor{enabledToolsAll: true, toolsLoaded: true}
	for _, n := range []string{"Bash", "WebFetch", "Write", "Edit"} {
		if !i.IsToolEnabled(n) {
			t.Fatalf("%s must be gated", n)
		}
	}
}
