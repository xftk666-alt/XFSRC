package evidence_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/evidence"
)

// buildPackScript builds a sealed, gate-approved evidence pack with the real
// Python gates. It is the only way to prove that the Go verifier and the Python
// signer agree byte-for-byte on canonical JSON and on the pack fingerprint.
const buildPackScript = `
import json, os, subprocess, sys
sys.path.insert(0, sys.argv[1])
import evidence_seal as es

out = sys.argv[2]
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

case("attack-read-b", "/api/Users/37", 200, json.dumps({"id": 37, "email": marker}), "ATOKEN")
case("control-unauth", "/api/Users/37", 401, '{"error":"unauthorized"}', "")
case("control-self", "/api/Users/1", 200, json.dumps({"id": 1, "email": "a@mybank-online.com"}), "ATOKEN")

comp_file = os.path.join(out, "compare-attack-read-b-vs-control-unauth.json")
json.dump({"attack": "attack-read-b", "control": "control-unauth", "pass": True, "checks": [
    {"name": "attack_status", "expected": 200, "pass": True},
    {"name": "control_status", "expected": 401, "pass": True},
    {"name": "attack_contains", "expected": marker, "pass": True},
    {"name": "bodies_differ", "expected": True, "pass": True},
]}, open(comp_file, "w"))

json.dump({"cases": [
    {"name": n, "dir": os.path.join(out, "cases", n), "url": f"https://{host}{p}",
     "status": 200, "method": "GET", "kind": "http"}
    for n, p in (("attack-read-b", "/api/Users/37"),
                 ("control-unauth", "/api/Users/37"),
                 ("control-self", "/api/Users/1"))],
    "compares": [{"attack": "attack-read-b", "control": "control-unauth",
                  "pass": True, "file": comp_file}]},
    open(os.path.join(out, "pack.json"), "w"))
es.seal_pack(out)

strict = os.path.join(sys.argv[1], "retest_strict.py")
def run(*args):
    p = subprocess.run(["python3", strict] + list(args), capture_output=True, text=True)
    if p.returncode != 0:
        sys.stderr.write(p.stdout + p.stderr)
        raise SystemExit(1)
    return json.loads(p.stdout)

g = run("gate", "--outdir", out, "--kind", "idor", "--victim-marker", marker,
        "--attack", "attack-read-b", "--control", "control-unauth")
if not g.get("ok"):
    sys.stderr.write(json.dumps(g, ensure_ascii=False))
    raise SystemExit(1)
run("signoff", "--outdir", out, "--phrase", "我已核验证据包并批准提交 " + g["challenge"])
v = run("verdict", "--outdir", out, "--verdict", "reproduced", "--submit-advice", "ready",
        "--summary", "t", "--victim-marker", marker, "--kind", "idor",
        "--attack", "attack-read-b", "--control", "control-unauth")
if not v.get("ok"):
    sys.stderr.write(json.dumps(v, ensure_ascii=False))
    raise SystemExit(1)
print("ok")
`

func buildPack(t *testing.T) (outdir, keyDir string) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	scripts := filepath.Join("..", "skills", "src-retest", "scripts")
	if _, err := os.Stat(filepath.Join(scripts, "retest_strict.py")); err != nil {
		t.Skipf("retest scripts unavailable: %v", err)
	}
	root := t.TempDir()
	runtime := filepath.Join(root, "runtime")
	if err := os.MkdirAll(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtime, ".hmac-key"), []byte("a123456789012345678901234567890123456789012345678901234567890123"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtime, ".recorder-token"), []byte("test-recorder-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	outdir = filepath.Join(root, "pack")
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "build.py")
	if err := os.WriteFile(script, []byte(buildPackScript), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", script, scripts, outdir)
	cmd.Env = append(os.Environ(),
		"ARTEX_EVIDENCE_TEST_ROOT="+runtime,
		"ARTEX_EVIDENCE_RECORDER_TOKEN=test-recorder-token",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build pack: %v\n%s", err, out)
	}
	return outdir, runtime
}

func TestVerdictMatchesPython(t *testing.T) {
	outdir, runtime := buildPack(t)
	key, err := evidence.LoadHMACKey(runtime)
	if err != nil {
		t.Fatal(err)
	}
	v, err := evidence.VerifyVerdict(outdir, key, "reproduced")
	if err != nil {
		t.Fatalf("Go verifier rejected a genuine Python-signed verdict: %v", err)
	}
	if !v.OK || v.Verdict != "reproduced" || !v.GateOK {
		t.Fatalf("unexpected verdict payload: %+v", v)
	}
	if v.Advice != "ready" {
		t.Fatalf("advice = %q, want ready", v.Advice)
	}
}

func TestVerdictRejectsTamperedEvidence(t *testing.T) {
	outdir, runtime := buildPack(t)
	key, err := evidence.LoadHMACKey(runtime)
	if err != nil {
		t.Fatal(err)
	}
	body := filepath.Join(outdir, "cases", "attack-read-b", "response.body")
	f, err := os.OpenFile(body, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\nTAMPERED\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := evidence.VerifyVerdict(outdir, key, "reproduced"); err == nil {
		t.Fatal("tampered evidence must invalidate the verdict")
	}
}

func TestVerdictRejectsWrongVerdictAndMissingFile(t *testing.T) {
	outdir, runtime := buildPack(t)
	key, err := evidence.LoadHMACKey(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.VerifyVerdict(outdir, key, "fixed"); err == nil {
		t.Fatal("verdict mismatch must be rejected")
	}
	empty := t.TempDir()
	if _, err := evidence.VerifyVerdict(empty, key, "reproduced"); err == nil {
		t.Fatal("missing verdict.json must be rejected")
	}
}

func TestVerdictRejectsForgedDocument(t *testing.T) {
	outdir, runtime := buildPack(t)
	key, err := evidence.LoadHMACKey(runtime)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(outdir, evidence.VerdictFile)
	if err := os.WriteFile(path, []byte(`{"kind":"verdict","payload":{"ok":true,"verdict":"reproduced","fingerprint":"x"},"hmac_sha256":"deadbeef"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.VerifyVerdict(outdir, key, "reproduced"); err == nil {
		t.Fatal("hand-written verdict.json must be rejected")
	}
}
