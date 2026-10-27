package server

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// packSeq keeps concurrent/subsequent packs in distinct directories.
var packSeq int

// retestPackScript builds a sealed, gate-approved evidence pack with the real
// Python gates, so server-side tests exercise the same artifacts the retester
// agent produces. Re-implementing the sealing in Go would let the two drift.
const retestPackScript = `
import json, os, subprocess, sys
sys.path.insert(0, sys.argv[1])
import evidence_seal as es

out, verdict = sys.argv[2], sys.argv[3]
host = "portal.mybank-online.com"
marker = "victim-b@mybank-online.com"

def case(name, path, status, body, auth):
    d = os.path.join(out, "cases", name)
    os.makedirs(d, exist_ok=True)
    url = f"https://{host}{path}"
    hdrs = f"GET {path} HTTP/1.1\nHost: {host}\n"
    if auth:
        hdrs += f"Authorization: Bearer {auth}\n"
    open(os.path.join(d, "request.txt"), "w").write(hdrs)
    open(os.path.join(d, "response_headers.txt"), "w").write(f"HTTP/1.1 {status} X\n")
    open(os.path.join(d, "response.body"), "w").write(body)
    json.dump({"ts": es._now(), "recorder": "artex-recorder/2", "recorder_seq": 1,
               "kind": "http", "url": url,
               "request": {"url": url, "method": "GET",
                           "headers_redacted": {"User-Agent": "artex-http-evidence/1.0"}},
               "response": {"status": status}},
              open(os.path.join(d, "meta.json"), "w"))
    es.seal_case(d)

if verdict == "reproduced":
    case("attack-read-b", "/api/Users/37", 200, json.dumps({"id": 37, "email": marker}), "ATOKEN")
    comp_pass = True
else:
    # Fixed: the attack no longer returns the victim's data, the control still works.
    case("attack-read-b", "/api/Users/37", 200, '{"error":"forbidden"}', "ATOKEN")
    comp_pass = False
case("control-unauth", "/api/Users/37", 401, '{"error":"unauthorized"}', "")
case("control-self", "/api/Users/1", 200, json.dumps({"id": 1, "email": "a@mybank-online.com"}), "ATOKEN")

comp_file = os.path.join(out, "compare-attack-read-b-vs-control-unauth.json")
json.dump({"attack": "attack-read-b", "control": "control-unauth", "pass": comp_pass, "checks": [
    {"name": "attack_status", "expected": 200, "pass": True},
    {"name": "control_status", "expected": 401, "pass": True},
    {"name": "attack_contains", "expected": marker, "pass": comp_pass},
    {"name": "bodies_differ", "expected": True, "pass": True},
]}, open(comp_file, "w"))

json.dump({"cases": [
    {"name": n, "dir": os.path.join(out, "cases", n), "url": f"https://{host}{p}",
     "status": 200, "method": "GET", "kind": "http"}
    for n, p in (("attack-read-b", "/api/Users/37"),
                 ("control-unauth", "/api/Users/37"),
                 ("control-self", "/api/Users/1"))],
    "compares": [{"attack": "attack-read-b", "control": "control-unauth",
                  "pass": comp_pass, "file": comp_file}]},
    open(os.path.join(out, "pack.json"), "w"))
es.seal_pack(out)

strict = os.path.join(sys.argv[1], "retest_strict.py")
def run(*args):
    p = subprocess.run(["python3", strict] + list(args), capture_output=True, text=True)
    return p.returncode, json.loads(p.stdout)

# For "fixed" the gate is EXPECTED to be ok=false (the attack no longer works),
# so only the verdict's own exit status decides success here.
run("gate", "--outdir", out, "--kind", "idor", "--victim-marker", marker,
    "--attack", "attack-read-b", "--control", "control-unauth")
rc, v = run("verdict", "--outdir", out, "--verdict", verdict, "--submit-advice", "needs-human",
            "--summary", "t", "--victim-marker", marker, "--kind", "idor",
            "--attack", "attack-read-b", "--control", "control-unauth")
if rc != 0 or not v.get("ok"):
    sys.stderr.write(json.dumps(v, ensure_ascii=False))
    raise SystemExit(1)
print("ok")
`

// buildRetestPack creates a signed evidence pack for verdict ("reproduced" or
// "fixed") under the server's work dir and returns its path.
func buildRetestPack(t *testing.T, s *Server, verdict string) string {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	scripts := filepath.Join("..", "skills", "src-retest", "scripts")
	if _, err := os.Stat(filepath.Join(scripts, "retest_strict.py")); err != nil {
		t.Skipf("retest scripts unavailable: %v", err)
	}
	key := "a123456789012345678901234567890123456789012345678901234567890123"
	runtime := filepath.Join(s.m.dir, "runtime")
	if err := os.MkdirAll(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtime, ".hmac-key"), []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtime, ".recorder-token"), []byte("test-recorder-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The verifier reads <evidence dir>/.hmac-key; point it at the same key the
	// Python gates used.
	evDir := filepath.Join(s.m.dir, "evidence")
	if err := os.MkdirAll(evDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evDir, ".hmac-key"), []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}

	// Unique per call: two packs in one test must not share a directory, or the
	// second build re-seals over the first and the first's fingerprint goes stale.
	packSeq++
	outdir := filepath.Join(s.m.dir, fmt.Sprintf("pack-%s-%d", verdict, packSeq))
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(runtime, "build.py")
	if err := os.WriteFile(script, []byte(retestPackScript), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", script, scripts, outdir, verdict)
	cmd.Env = append(os.Environ(),
		"ARTEX_EVIDENCE_TEST_ROOT="+runtime,
		"ARTEX_EVIDENCE_RECORDER_TOKEN=test-recorder-token",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build pack: %v\n%s", err, out)
	}
	return outdir
}
