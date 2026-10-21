package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
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
	// Short/obfuscated IPv4 forms that inet_aton accepts and that every libc
	// resolver also accepts: "127.1", "10.1", "0x7f000001", "2130706433". Without
	// these, `curl 127.1` extracted no host at all and the gate allowed it.
	ipv4VariantPattern = regexp.MustCompile(`(?i)\b(?:0x[0-9a-f]{1,8}|\d{1,10})(?:\.(?:0x[0-9a-f]{1,8}|\d{1,10})){0,3}\b`)
	hostPattern        = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
	// host:port where host is a single label ("juice-shop:3000", "localhost:3000").
	// Single-label targets are normal in lab/container setups and were previously
	// invisible to the gate. Only consulted when the command also names a network
	// tool, so `docker run -p 8080:80` is not mistaken for a target.
	singleLabelHostPort = regexp.MustCompile(`(?i)\b([a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?):(\d{1,5})\b`)
)

// networkTools are command names whose arguments are network targets. Used to
// decide whether a bare "host:port" token is a target rather than a compose port
// mapping or a time-of-day.
var networkTools = map[string]bool{
	"curl": true, "wget": true, "httpie": true, "http": true, "https": true,
	"nc": true, "ncat": true, "netcat": true, "telnet": true, "ssh": true,
	"scp": true, "sftp": true, "dig": true, "host": true, "nslookup": true,
	"ping": true, "traceroute": true, "nmap": true, "masscan": true,
	"httpx": true, "nuclei": true, "naabu": true, "katana": true, "ffuf": true,
	"gobuster": true, "feroxbuster": true, "dirsearch": true, "nikto": true,
	"sqlmap": true, "hydra": true, "whatweb": true, "wafw00f": true,
	"subfinder": true, "amass": true, "dnsx": true, "gospider": true,
	"wfuzz": true, "arjun": true, "dalfox": true, "xsstrike": true,
}

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
	for _, tok := range ipv4VariantPattern.FindAllString(raw, -1) {
		if ip := ipv4Variant(tok); ip != "" {
			add(ip)
		}
	}
	// Single-label targets ("juice-shop:3000", "localhost:3000") only count when
	// the command actually names a network tool.
	if mentionsNetworkTool(raw) {
		for _, m := range singleLabelHostPort.FindAllStringSubmatch(raw, -1) {
			if port, ok := atoiPort(m[2]); !ok || port == 0 {
				continue
			}
			host := strings.ToLower(m[1])
			if host == "http" || host == "https" || host == "ftp" || host == "file" {
				continue
			}
			add(host)
		}
	}
	return out
}

// mentionsNetworkTool reports whether the command text invokes one of networkTools
// (optionally through a wrapper such as `bash proxy_exec.sh curl ...`).
func mentionsNetworkTool(raw string) bool {
	for _, tok := range shellTokens(raw) {
		base := strings.ToLower(tok)
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			base = base[i+1:]
		}
		if networkTools[base] {
			return true
		}
	}
	return false
}

func atoiPort(s string) (int, bool) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
		if n > 65535 {
			return 0, false
		}
	}
	return n, len(s) > 0
}

// ipv4Variant normalises an inet_aton-style IPv4 literal ("127.1", "0x7f000001",
// "2130706433") to dotted-quad. Returns "" when the value is not an IPv4 literal
// (plain integers such as a port number or a count are rejected by the range
// check).
func ipv4Variant(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) > 4 {
		return ""
	}
	vals := make([]uint64, 0, 4)
	for _, p := range parts {
		v, ok := parseIPv4Part(p)
		if !ok {
			return ""
		}
		vals = append(vals, v)
	}
	var a, b, c, d uint64
	switch len(vals) {
	case 1:
		// A bare integer is only an address when it cannot be a port/count/date:
		// inet_aton reads "3000" as 0.0.11.184, which would make every `-p 3000`
		// look like a target. Values at or above 1<<24 are unambiguous encodings
		// (e.g. 2130706433 = 127.0.0.1).
		if vals[0] < 1<<24 || vals[0] > 0xffffffff {
			return ""
		}
		a, b, c, d = vals[0]>>24, (vals[0]>>16)&0xff, (vals[0]>>8)&0xff, vals[0]&0xff
	case 2:
		if vals[0] > 0xff || vals[1] > 0xffffff {
			return ""
		}
		a, b, c, d = vals[0], vals[1]>>16, (vals[1]>>8)&0xff, vals[1]&0xff
	case 3:
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff {
			return ""
		}
		a, b, c, d = vals[0], vals[1], vals[2]>>8, vals[2]&0xff
	case 4:
		for _, v := range vals {
			if v > 0xff {
				return ""
			}
		}
		a, b, c, d = vals[0], vals[1], vals[2], vals[3]
	default:
		return ""
	}
	// Short forms are only interesting when they reach the host itself: an
	// abbreviated address can only be a target if it lands in loopback/private/
	// link-local space, and restricting to that range keeps version strings such
	// as "1.5" from being read as 1.0.0.5.
	if len(vals) < 4 && !isNonPublicIPv4(a, b, c, d) {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

func isNonPublicIPv4(a, b, c, d uint64) bool {
	ip := net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", a, b, c, d))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func parseIPv4Part(p string) (uint64, bool) {
	if p == "" {
		return 0, false
	}
	base := 10
	if strings.HasPrefix(strings.ToLower(p), "0x") {
		base = 16
		p = p[2:]
	} else if len(p) > 1 && p[0] == '0' {
		base = 8
		p = p[1:]
	}
	if p == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(p, base, 32)
	if err != nil {
		return 0, false
	}
	return v, true
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
