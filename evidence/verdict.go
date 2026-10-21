// Package evidence: retest verdict verification.
//
// The retest gates (skills/src-retest/scripts/retest_strict.py) are the only
// component that decides whether a finding is reproduced or fixed, and they seal
// their decisions with HMAC. Historically the Go side trusted whatever the model
// passed to record_finding_retest_result, so an agent could skip the gates
// entirely and write "reproduced" — or "fixed", which closes the finding.
//
// This file re-implements exactly the parts of the Python sealing scheme the
// server needs to check that a decision exists, is signed with the platform key,
// and still matches the evidence on disk:
//
//	document    = {"kind": ..., "payload": {...}} signed as HMAC-SHA256(key, canonical)
//	canonical   = JSON with sorted keys, separators (",", ":"), UTF-8 (no \u escapes)
//	fingerprint = sha256 over "pack:<sha>" + per-case "body|shot|seal:<name>:<sha>"
//
// The canonical form must stay byte-identical to evidence_seal.canonical() and
// retest_strict.pack_fingerprint(); TestVerdictMatchesPython pins it against the
// real Python implementation.
package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// VerdictFile is the signed decision document written by retest_strict.py.
const VerdictFile = "verdict.json"

// PackSealFile is the sealed digest of pack.json.
const PackSealFile = "pack.seal.json"

// HMACKeyFile is the platform evidence key (same file the Python gates read).
const HMACKeyFile = ".hmac-key"

// Verdict is the verified content of a signed verdict.json.
type Verdict struct {
	Kind        string
	OK          bool
	Rejected    bool
	Verdict     string
	Advice      string
	Fingerprint string
	GateOK      bool
	SignedOff   bool
	Lab         bool
	Raw         map[string]any
}

// CanonicalJSON renders v the way Python's
// json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":")) does.
// Go marshals map keys in sorted order already; the only difference left is HTML
// escaping, which Python does not do.
func CanonicalJSON(v any) ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := strings.TrimSuffix(buf.String(), "\n")
	// encoding/json always escapes U+2028/U+2029 (a JS-safety rule), while
	// Python's json.dumps with ensure_ascii=False leaves them literal. The
	// signatures must agree byte for byte, so undo that escaping: a payload
	// containing either character otherwise produced a different HMAC on each
	// side and the Go verifier rejected a pack Python had legitimately sealed.
	out = strings.ReplaceAll(out, `\u2028`, "\u2028")
	out = strings.ReplaceAll(out, `\u2029`, "\u2029")
	return []byte(out), nil
}

// LoadHMACKey reads the evidence signing key from the first readable candidate.
// The environment is deliberately not consulted: a key path chosen by an agent
// would let it re-sign a forged pack.
func LoadHMACKey(dirs ...string) ([]byte, error) {
	candidates := make([]string, 0, len(dirs)+1)
	for _, d := range dirs {
		if strings.TrimSpace(d) == "" {
			continue
		}
		candidates = append(candidates, filepath.Join(d, HMACKeyFile))
	}
	candidates = append(candidates, filepath.Join("/app/data/evidence", HMACKeyFile))
	for _, p := range candidates {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		key := strings.TrimSpace(string(raw))
		if len(key) < 32 {
			return nil, fmt.Errorf("证据密钥过短（%s）", p)
		}
		return []byte(key), nil
	}
	return nil, errors.New("找不到证据 HMAC 密钥：复测闸门未初始化")
}

// VerifyDocument checks one sealed document ({"kind","payload","hmac_sha256"}).
func VerifyDocument(path string, key []byte) (string, map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	var doc struct {
		Kind    string         `json:"kind"`
		Payload map[string]any `json:"payload"`
		MAC     string         `json:"hmac_sha256"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", nil, fmt.Errorf("%s 无法解析: %w", filepath.Base(path), err)
	}
	if doc.Kind == "" || doc.Payload == nil || doc.MAC == "" {
		return "", nil, fmt.Errorf("%s 不是已签名的文档（缺 kind/payload/hmac_sha256）", filepath.Base(path))
	}
	canon, err := CanonicalJSON(map[string]any{"kind": doc.Kind, "payload": doc.Payload})
	if err != nil {
		return "", nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canon)
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(strings.ToLower(doc.MAC))) {
		return "", nil, fmt.Errorf("%s HMAC 不匹配（伪造或密钥不符）", filepath.Base(path))
	}
	return doc.Kind, doc.Payload, nil
}

// fileSHA256 returns the hex digest of a file, or "" when it cannot be read.
func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// PackFingerprint mirrors retest_strict.pack_fingerprint: pack.json plus every
// case body/screenshot/seal, in sorted case order.
func PackFingerprint(outdir string) (string, error) {
	parts := []string{}
	packSHA := fileSHA256(filepath.Join(outdir, "pack.json"))
	if packSHA == "" {
		packSHA = "missing"
	}
	parts = append(parts, "pack:"+packSHA)
	casesDir := filepath.Join(outdir, "cases")
	entries, err := os.ReadDir(casesDir)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		dir := filepath.Join(casesDir, name)
		if sha := fileSHA256(filepath.Join(dir, "response.body")); sha != "" {
			parts = append(parts, "body:"+name+":"+sha)
		}
		if sha := fileSHA256(filepath.Join(dir, "screenshot.png")); sha != "" {
			parts = append(parts, "shot:"+name+":"+sha)
		}
		if sha := fileSHA256(filepath.Join(dir, "seal.json")); sha != "" {
			parts = append(parts, "seal:"+name+":"+sha)
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:]), nil
}

// VerifyVerdict loads and verifies <outdir>/verdict.json, then checks that it
// still describes the evidence in <outdir> and that its decision matches the
// verdict the caller is about to record.
func VerifyVerdict(outdir string, key []byte, wantVerdict string) (*Verdict, error) {
	path := filepath.Join(outdir, VerdictFile)
	kind, payload, err := VerifyDocument(path, key)
	if err != nil {
		return nil, fmt.Errorf("复测结论未通过证据校验: %w", err)
	}
	if kind != "verdict" {
		return nil, fmt.Errorf("复测结论文档类型是 %q，不是 verdict", kind)
	}
	v := &Verdict{Kind: kind, Raw: payload}
	v.OK, _ = payload["ok"].(bool)
	v.Rejected, _ = payload["rejected"].(bool)
	v.Verdict, _ = payload["verdict"].(string)
	v.Advice, _ = payload["submit_advice"].(string)
	v.Fingerprint, _ = payload["fingerprint"].(string)
	v.GateOK, _ = payload["gate_ok"].(bool)
	v.SignedOff, _ = payload["signed_off"].(bool)
	v.Lab, _ = payload["lab"].(bool)

	if !v.OK || v.Rejected {
		reasons := ""
		if rs, ok := payload["errors"].([]any); ok && len(rs) > 0 {
			parts := make([]string, 0, len(rs))
			for _, r := range rs {
				parts = append(parts, fmt.Sprint(r))
			}
			reasons = "：" + strings.Join(parts, "；")
		}
		return nil, fmt.Errorf("复测闸门否决了这次结论%s", reasons)
	}
	if wantVerdict != "" && v.Verdict != wantVerdict {
		return nil, fmt.Errorf("保存的结论是 %q，与闸门签发的 %q 不一致", wantVerdict, v.Verdict)
	}
	live, err := PackFingerprint(outdir)
	if err != nil {
		return nil, err
	}
	if v.Fingerprint == "" || v.Fingerprint != live {
		return nil, errors.New("证据包在签发结论后被改动（指纹不一致），请重新跑闸门")
	}
	return v, nil
}
