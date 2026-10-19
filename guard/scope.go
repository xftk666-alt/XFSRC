package guard

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
)

// ScopeChecker decides whether a tool call's network targets are authorized.
// A non-empty blocked list OR a non-empty reason denies the call (the latter is
// used for fail-closed verdicts where no host could be extracted).
// Implementations must fail closed.
type ScopeChecker func(ctx context.Context, tool string, input []byte) (blocked []string, reason string)

var (
	urlPattern  = regexp.MustCompile(`(?i)\bhttps?://[^\s'"<>|;)]+`)
	ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	hostPattern = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
)

// hostOnlyFiles lists filename-like suffixes that must not be mistaken for a
// hostname (e.g. "common.txt", "app.js"). Without this, wordlist paths would be
// rejected as out-of-scope targets.
var hostOnlyFiles = map[string]bool{
	"txt": true, "json": true, "jsonl": true, "py": true, "sh": true, "js": true,
	"ts": true, "tsx": true, "jsx": true, "md": true, "csv": true, "xml": true,
	"yaml": true, "yml": true, "conf": true, "log": true, "pem": true, "crt": true,
	"cer": true, "key": true, "zip": true, "gz": true, "tar": true, "html": true,
	"htm": true, "php": true, "asp": true, "aspx": true, "jsp": true, "go": true,
	"lock": true, "sqlite": true, "db": true, "out": true, "err": true, "tmp": true,
	"bak": true, "old": true, "png": true, "jpg": true, "jpeg": true, "gif": true,
	"svg": true, "ico": true, "woff": true, "woff2": true, "ttf": true, "map": true,
}

// ExtractHosts pulls candidate network targets out of a tool call. It is
// intentionally conservative: URLs, IPv4 literals and dotted hostnames are
// collected; quoted file paths with ordinary extensions are ignored.
func ExtractHosts(tool string, input []byte) []string {
	var raw string
	switch tool {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(input, &in) == nil {
			raw = in.Command
		}
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(input, &in) == nil {
			raw = in.Text
		}
	case "WebFetch":
		var in struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(input, &in) == nil {
			raw = in.URL
		}
	default:
		raw = strings.Join(jsonStrings(input), "\n")
	}
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = normalizeHost(h)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, u := range urlPattern.FindAllString(raw, -1) {
		add(hostFromURL(u))
	}
	for _, ip := range ipv4Pattern.FindAllString(raw, -1) {
		add(ip)
	}
	for _, h := range hostPattern.FindAllString(raw, -1) {
		if isFileName(h) || looksLikeToken(h) {
			continue
		}
		add(h)
	}
	return out
}

func jsonStrings(input []byte) []string {
	var v any
	if json.Unmarshal(input, &v) != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// looksLikeToken rejects base64/JWT blobs that happen to match the dotted
// hostname pattern (e.g. "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"). Real DNS
// labels are lowercase in practice and never mix case with digits at this
// length; tokens always do.
func looksLikeToken(h string) bool {
	for _, label := range strings.Split(h, ".") {
		if len(label) < 20 {
			continue
		}
		var upper, lower, digit bool
		for _, r := range label {
			switch {
			case r >= 'A' && r <= 'Z':
				upper = true
			case r >= 'a' && r <= 'z':
				lower = true
			case r >= '0' && r <= '9':
				digit = true
			}
		}
		if upper && lower && digit {
			return true
		}
	}
	return false
}

func isFileName(h string) bool {
	dot := strings.LastIndexByte(h, '.')
	if dot <= 0 || dot == len(h)-1 {
		return false
	}
	return hostOnlyFiles[strings.ToLower(h[dot+1:])]
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.Trim(h, "[]")
	if h == "" || strings.ContainsAny(h, " /\\") {
		return ""
	}
	if i := strings.IndexByte(h, ':'); i >= 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	return strings.TrimSuffix(h, ".")
}

func hostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	return raw
}
