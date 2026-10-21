package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/intercept"
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
	// Collect URL spans first so the raw-text host scan below does not re-read
	// their contents. Without masking, "http://allowed.com:pw@internal/x" also
	// yielded "allowed.com" from the userinfo — an extra target that no scope
	// entry needs and that would block the call.
	urlSpans := urlPattern.FindAllStringIndex(raw, -1)
	inURL := func(pos int) bool {
		for _, s := range urlSpans {
			if pos >= s[0] && pos < s[1] {
				return true
			}
		}
		return false
	}
	for _, span := range urlSpans {
		add(hostFromURL(raw[span[0]:span[1]]))
	}
	for _, ip := range ipv4Pattern.FindAllString(raw, -1) {
		add(ip)
	}
	for _, loc := range hostPattern.FindAllStringIndex(raw, -1) {
		if inURL(loc[0]) {
			continue
		}
		h := raw[loc[0]:loc[1]]
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
	// Single-label targets ("juice-shop:3000", "localhost:3000", "localhost").
	// Only consulted when the command actually names a network tool, so
	// `docker run -p 8080:80` is not mistaken for a target.
	if mentionsNetworkTool(raw) {
		// The regexp is applied to raw text, so `api.example.com:8443` also
		// matches `com:8443` at the dot boundary (Go's RE2 has no lookbehind).
		// Accept a match only when the character before it is not part of a
		// hostname — otherwise every port-qualified URL grew a bogus TLD target
		// that no scope entry could ever contain, blocking all of them.
		for _, m := range singleLabelHostPort.FindAllStringSubmatchIndex(raw, -1) {
			start := m[2] // group 1 (host) start
			if start > 0 && isHostByte(raw[start-1]) {
				continue
			}
			port := raw[m[4]:m[5]]
			if p, ok := atoiPort(port); !ok || p == 0 {
				continue
			}
			host := strings.ToLower(raw[m[2]:m[3]])
			if host == "http" || host == "https" || host == "ftp" || host == "file" {
				continue
			}
			add(host)
		}
		// Operand pass: a network tool's non-flag arguments are targets even when
		// they carry no port and look like filenames ("curl localhost",
		// "nmap evil.zip", "nmap Evil1234567890.com"). The dotted-host regexp
		// above cannot see them (no dot / filtered as a filename), which made
		// each of those a silent gate bypass.
		for _, op := range networkOperands(raw) {
			add(op)
		}
	}
	return out
}

// isHostByte reports whether b can be part of a hostname label. Used to reject
// host:port matches that begin mid-hostname.
func isHostByte(b byte) bool {
	return b == '.' || b == '-' || b == '_' ||
		(b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// valueFlags lists flags that consume the following token as their value. Needed
// so an output filename ("curl -o out.html URL") is not read as a target. Flags
// not listed are assumed boolean; an unlisted value-taking flag can only cause an
// extra candidate (a visible block), never a missed one.
var valueFlags = map[string]bool{
	"-o": true, "-w": true, "-l": true, "-u": true, "-H": true, "-d": true,
	"-X": true, "-A": true, "-e": true, "-b": true, "-c": true, "-T": true,
	"-F": true, "-x": true, "-p": true, "-sU": true, "-r": true, "-t": true,
	"-m": true, "-iL": true, "-iR": true, "-oN": true, "-oX": true, "-oG": true,
	"-oA": true, "-Pn": true, "-pU": true, "-pS": true, "-g": true,
	"--output": true, "--wordlist": true, "--url": true, "--target": true,
	"--targets": true, "--list": true, "--header": true, "--data": true,
	"--cookie": true, "--user-agent": true, "--proxy": true, "--input": true,
	"--inputlist": true, "--url-file": true, "--target-file": true,
	"--rate": true, "--threads": true, "--concurrency": true, "--timeout": true,
	"--severity": true, "--tags": true, "--templates": true, "--resolvers": true,
}

// wrapperCommands are words that introduce a command rather than name a target.
// Without this the operand pass reads "curl" / "nmap" themselves as hosts.
var wrapperCommands = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "sudo": true,
	"env": true, "command": true, "builtin": true, "exec": true, "time": true,
	"xargs": true, "nohup": true, "timeout": true, "stdbuf": true, "proxychains": true,
	"proxychains4": true, "watch": true, "nice": true, "setsid": true,
}

// networkOperands returns the arguments of network tools that should be treated
// as targets: every non-flag token not consumed as a flag value. It strips a
// scheme, userinfo, path and port before returning the host.
//
// A token only counts as a target when it sits in a network tool's own argument
// list (or has a dotted/port-qualified shape). Treating every bare word in a
// pipeline as a host made `echo … | base64 -d | xargs curl` report "echo" and
// "base64" as targets, which blocks legitimate calls.
func networkOperands(raw string) []string {
	tokens := shellTokens(raw)
	var out []string
	// direct: the next bare token belongs to a network tool's argument list.
	direct := false
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if strings.HasPrefix(tok, "-") {
			if strings.Contains(tok, "=") {
				continue // "--flag=value": the value is inline
			}
			if valueFlags[tok] || valueFlags[strings.ToLower(tok)] {
				i++ // skip the value
			}
			continue
		}
		base := strings.ToLower(tok)
		if j := strings.LastIndexByte(base, '/'); j >= 0 {
			base = base[j+1:]
		}
		if networkTools[base] {
			direct = true
			continue
		}
		if wrapperCommands[base] {
			continue // the wrapper itself is not a target
		}
		if h := operandHost(tok); h != "" && (direct || looksLikeHostShape(tok)) {
			out = append(out, h)
		}
		// A bare word that is not host-shaped ends the tool's argument run: it is
		// the next command in the pipeline (`… | base64 -d | xargs curl`).
		direct = false
	}
	return out
}

// looksLikeHostShape reports whether a token is unambiguous enough to be a
// target on its own: it has a dot, a port, or is an IP literal.
func looksLikeHostShape(tok string) bool {
	if strings.ContainsAny(tok, ".:") {
		return true
	}
	return strings.EqualFold(tok, "localhost")
}

// operandHost reduces one command operand to a host, or "" when it is not a
// target. Unlike the raw-text scans it applies no filename/token heuristic:
// position in the command is the evidence, so "evil.zip" and mixed-case labels
// stay visible.
func operandHost(tok string) string {
	tok = strings.Trim(tok, `"'`)
	if tok == "" || strings.ContainsAny(tok, " \t\\") {
		return ""
	}
	if strings.Contains(tok, "://") {
		return hostFromURL(tok)
	}
	// Drop userinfo the way a URL parser would.
	if at := strings.LastIndexByte(tok, '@'); at >= 0 {
		tok = tok[at+1:]
	}
	// Drop a path/query/fragment: "localhost/admin" targets localhost. An
	// operand that starts with '/' is a filesystem path, not a host.
	if i := strings.IndexAny(tok, "/?#"); i == 0 {
		return ""
	} else if i > 0 {
		tok = tok[:i]
	}
	if tok == "" {
		return ""
	}
	// A bare path-looking operand ("run.py", "payload.sh") is a script, not a
	// target; the script's own contents are scanned separately. An extensionless
	// name has no ext at all — slicing Ext()[1:] there panics.
	if ext := filepath.Ext(tok); ext != "" && !strings.Contains(tok, ":") {
		if hostOnlyFiles[strings.ToLower(ext[1:])] && !looksLikeHostname(tok) {
			return ""
		}
	}
	// inet_aton-style literals ("127.1", "0x7f000001", "2130706433") must reduce to
	// the dotted quad, or they would be compared against scope entries in a form
	// no entry ever uses.
	if ip := ipv4Variant(tok); ip != "" {
		return ip
	}
	h := normalizeHost(tok)
	if h == "" {
		return ""
	}
	// Only host-shaped characters may survive: this drops shell punctuation that
	// stayed attached to a token (";", "&&", ")").
	for _, r := range h {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' || r == ':' {
			continue
		}
		return ""
	}
	// Reject operands that are clearly not hosts: pure numbers, version strings.
	if _, err := strconv.ParseFloat(h, 64); err == nil {
		return ""
	}
	return h
}

// looksLikeHostname reports whether s has a dotted, DNS-shaped tail. Used to keep
// operandHost from treating "run.py" as a target while still accepting
// "evil.zip" — the difference is whether the last label is a plausible TLD.
func looksLikeHostname(s string) bool {
	dot := strings.LastIndexByte(s, '.')
	if dot <= 0 || dot == len(s)-1 {
		return false
	}
	tld := strings.ToLower(s[dot+1:])
	if len(tld) < 2 || len(tld) > 24 {
		return false
	}
	for _, r := range tld {
		if !(r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
}

// ScriptHosts extracts network targets from the scripts a tool call would
// execute. Without this the gate only sees the command line, so
// `python3 /tmp/recon.py` — and the tool prompt itself recommends writing a
// script for anything non-trivial — carried its targets invisibly.
//
// The second return is a fail-closed reason: a script whose body could not be
// read in full may hide targets, so the call is denied rather than guessed at.
func ScriptHosts(ctx context.Context, tool string, input []byte) (hosts []string, blockReason string) {
	scripts, status := intercept.CaptureScripts(intercept.WorkingDir(ctx), tool, input)
	if len(scripts) == 0 {
		return nil, ""
	}
	var out []string
	for _, s := range scripts {
		if s.Content != "" {
			out = append(out, extractFromText(s.Content)...)
		}
		if s.ReadError != "" || !s.Complete || s.Truncated {
			detail := s.ReadError
			if detail == "" {
				detail = "内容不完整"
			}
			return out, "脚本内容无法完整读取，无法确认其中的目标，已按 fail-closed 阻止：" +
				s.Path + "（" + detail + "）"
		}
	}
	if status == "incomplete" && len(out) == 0 {
		return nil, "脚本内容无法完整读取，无法确认其中的目标，已按 fail-closed 阻止"
	}
	return out, ""
}

// scriptNetworkIndicators are tokens that mean "this line talks to the network".
// Script bodies are full source code, so scanning them for any dotted identifier
// would flag `urllib.request` or `os.path.join` as targets. A host only counts
// when its line shows it is being connected to.
var scriptNetworkIndicators = []string{
	"curl", "wget", "httpie", "nc ", "ncat", "netcat", "telnet", "ssh ", "scp ",
	"sftp", "dig ", "nslookup", "nmap", "masscan", "httpx", "nuclei", "naabu",
	"katana", "ffuf", "gobuster", "feroxbuster", "dirsearch", "nikto", "sqlmap",
	"hydra", "whatweb", "wafw00f", "subfinder", "amass", "dnsx", "gospider",
	"wfuzz", "arjun", "dalfox", "xsstrike",
	"urlopen", "requests.", "http.client", "httpx.", "socket.",
	"fetch(", "axios", "got(", "request(", "http.Get", "http.Post",
	"net/http", "Invoke-WebRequest", "Invoke-RestMethod",
}

// extractFromText pulls targets out of a script body.
//
// URLs and IP literals are taken from anywhere; a bare dotted host is taken only
// from a line that also names a network call, so ordinary source code does not
// turn every package path into a scope violation.
func extractFromText(text string) []string {
	if strings.TrimSpace(text) == "" {
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
	for _, line := range strings.Split(text, "\n") {
		// URLs and IPs are unambiguous wherever they appear.
		for _, u := range urlPattern.FindAllString(line, -1) {
			add(hostFromURL(u))
		}
		for _, ip := range ipv4Pattern.FindAllString(line, -1) {
			add(ip)
		}
		if !lineMentionsNetwork(line) {
			continue
		}
		// A dotted host on a network line counts only when it is quoted — i.e.
		// used as a value ("evil.example") — or when it is an operand of a
		// network command. Scanning the whole line instead turned module paths
		// like `import urllib.request` into scope violations.
		for _, h := range quotedHosts(line) {
			add(h)
		}
		if mentionsNetworkTool(line) {
			for _, op := range networkOperands(line) {
				add(op)
			}
		}
	}
	return out
}

// quotedHosts returns dotted hosts that appear inside single or double quotes.
func quotedHosts(line string) []string {
	var out []string
	for i := 0; i < len(line); i++ {
		q := line[i]
		if q != '\'' && q != '"' && q != '`' {
			continue
		}
		end := strings.IndexByte(line[i+1:], q)
		if end < 0 {
			break
		}
		body := line[i+1 : i+1+end]
		for _, h := range hostPattern.FindAllString(body, -1) {
			if isFileName(h) || looksLikeToken(h) {
				continue
			}
			out = append(out, h)
		}
		i += end + 1
	}
	return out
}

// lineMentionsNetwork reports whether a source line shows network activity.
func lineMentionsNetwork(line string) bool {
	low := strings.ToLower(line)
	for _, ind := range scriptNetworkIndicators {
		if strings.Contains(low, strings.ToLower(ind)) {
			return true
		}
	}
	return false
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

// normalizeHost lowercases and strips a port, brackets and a trailing dot. It is
// deliberately conservative: a host containing whitespace or a path separator is
// rejected rather than guessed at.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" || strings.ContainsAny(h, " /\\") {
		return ""
	}
	// Bracketed IPv6: "[::1]" or "[::1]:8080". Trim brackets first, then any port
	// that followed the closing bracket. Stripping "[]" from both ends (the old
	// behaviour) turned "[::1]:8080" into "::1]:8080", which never matched.
	if strings.HasPrefix(h, "[") {
		if end := strings.IndexByte(h, ']'); end > 0 {
			host := h[1:end]
			if net.ParseIP(host) != nil {
				return strings.TrimSuffix(host, ".")
			}
			return ""
		}
		return ""
	}
	// Bare IPv6 literal: two or more colons and no brackets. Keep as-is.
	if strings.Count(h, ":") >= 2 {
		if net.ParseIP(h) != nil {
			return strings.TrimSuffix(h, ".")
		}
		return ""
	}
	// host:port
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return strings.TrimSuffix(h, ".")
}

// hostFromURL returns the host a URL points at.
//
// It parses with net/url so userinfo is handled the way a browser handles it:
// "http://allowed.com:pw@internal/x" targets "internal", not "allowed.com".
// Returning the userinfo (as the old hand-rolled split did) let a call target an
// out-of-scope host while the gate only ever checked an in-scope one.
func hostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}
