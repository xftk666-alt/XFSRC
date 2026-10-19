package guard

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/intercept"
)

// Target files are the blind spot of argument-only extraction: `cat targets.txt
// | httpx` or `nuclei -l targets.txt` carry the real hosts inside a file, so the
// gate would otherwise see no target at all and allow the call.
const (
	maxTargetFileBytes = 2 << 20 // 2 MiB
	maxTargetFileLines = 20000
)

// targetFileFlag maps a flag to the tool names it applies to. A nil set means
// "any tool". Flags deliberately NOT listed: -w (wordlist: payloads, not
// targets), -o (output), -l for sqlmap (its -l is a log file).
var targetFileFlag = map[string]map[string]bool{
	"-l":           {"httpx": true, "nuclei": true, "katana": true, "naabu": true},
	"-list":        {"httpx": true, "nuclei": true, "katana": true, "naabu": true},
	"-il":          {"nmap": true},
	"-dl":          {"subfinder": true},
	"-input":       nil,
	"-inputlist":   nil,
	"-targets":     nil,
	"-target-file": nil,
	"--url-file":   nil,
}

// FileHosts scans the target-list files referenced by a tool call. It returns
// the hosts found inside them plus a non-empty reason when the call must be
// blocked (unreadable target list → fail closed).
func FileHosts(ctx context.Context, tool string, input []byte) (hosts []string, blockReason string) {
	command, ok := commandText(tool, input)
	if !ok || strings.TrimSpace(command) == "" {
		return nil, ""
	}
	dir := intercept.WorkingDir(ctx)
	for _, ref := range targetFilesIn(command) {
		path := ref
		if !filepath.IsAbs(path) {
			if dir == "" {
				// Without a bound working directory we cannot resolve the path,
				// so we cannot prove the targets are in scope.
				return nil, "目标列表使用相对路径且无法确定工作目录，已按 fail-closed 阻止：" + ref
			}
			path = filepath.Join(dir, path)
		}
		found, err := readTargetHosts(path)
		if err != nil {
			return nil, "目标列表无法读取，已按 fail-closed 阻止：" + ref + "（" + err.Error() + "）"
		}
		hosts = append(hosts, found...)
	}
	return hosts, ""
}

// commandText returns the executable text of a tool call (Bash command, shell
// text, or a best-effort join of the call's string arguments).
func commandText(tool string, input []byte) (string, bool) {
	switch tool {
	case "Bash", "shell_open":
		return jsonField(input, "command")
	case "shell_send":
		return jsonField(input, "text")
	}
	if s, ok := jsonField(input, "command"); ok {
		return s, true
	}
	return "", false
}

func jsonField(input []byte, key string) (string, bool) {
	var in map[string]any
	if json.Unmarshal(input, &in) != nil {
		return "", false
	}
	v, ok := in[key].(string)
	return v, ok
}

// targetFilesIn extracts file paths passed to target-list flags, plus files fed
// through `cat FILE |`, `< FILE`, and `xargs ... < FILE`.
func targetFilesIn(command string) []string {
	tokens := shellTokens(command)
	var out []string
	for i, tok := range tokens {
		name := strings.ToLower(tok)
		if tools, ok := targetFileFlag[name]; ok {
			if tools != nil && !toolMatches(tokens, tools) {
				continue
			}
			if i+1 < len(tokens) {
				// katana shares -u/-list, so a value may be a URL rather than a
				// file. URLs are already covered by argument extraction.
				if p := cleanPathToken(tokens[i+1]); p != "" && !strings.Contains(p, "://") {
					out = append(out, p)
				}
			}
			continue
		}
		// `cat targets.txt | httpx` / `xargs -a targets.txt`
		if name == "cat" && i+1 < len(tokens) {
			if p := cleanPathToken(tokens[i+1]); p != "" && looksLikePath(p) {
				out = append(out, p)
			}
		}
		if name == "-a" && i > 0 && strings.EqualFold(tokens[i-1], "xargs") && i+1 < len(tokens) {
			if p := cleanPathToken(tokens[i+1]); p != "" {
				out = append(out, p)
			}
		}
		// `< targets.txt` (tokenizer keeps the operator separate from its path)
		if tok == "<" || tok == "0<" {
			if i+1 < len(tokens) {
				if p := cleanPathToken(tokens[i+1]); p != "" {
					out = append(out, p)
				}
			}
			continue
		}
		if strings.HasPrefix(tok, "<") && len(tok) > 1 {
			if p := cleanPathToken(strings.TrimPrefix(tok, "<")); p != "" {
				out = append(out, p)
			}
		}
	}
	return dedupe(out)
}

// toolMatches reports whether any token names one of the tools the flag
// belongs to (the command may be wrapped: `bash proxy_exec.sh httpx ...`).
func toolMatches(tokens []string, tools map[string]bool) bool {
	for _, tok := range tokens {
		base := strings.ToLower(filepath.Base(tok))
		if tools[base] {
			return true
		}
	}
	return false
}

func cleanPathToken(tok string) string {
	tok = strings.TrimSpace(tok)
	tok = strings.Trim(tok, `"'`)
	tok = strings.TrimPrefix(tok, "<")
	tok = strings.TrimPrefix(tok, ">")
	if tok == "" || strings.HasPrefix(tok, "-") || strings.ContainsAny(tok, "|&;") {
		return ""
	}
	return tok
}

func looksLikePath(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") {
		return true
	}
	return strings.Contains(p, "/") || hostOnlyFiles[strings.ToLower(filepath.Ext(p)[1:])]
}

// readTargetHosts reads one target list and returns the hosts it contains.
// Files that parse as something else (wordlists, payload lists) yield nothing:
// they are not an authorization source.
func readTargetHosts(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, nil
	}
	if fi.Size() > maxTargetFileBytes {
		return nil, nil // too large to be a curated target list
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxTargetFileLines {
		lines = lines[:maxTargetFileLines]
	}
	var hosts []string
	valid, total := 0, 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		total++
		if h, ok := parseTargetLine(line); ok {
			valid++
			hosts = append(hosts, h)
		}
	}
	// A file where most lines are not hosts is a wordlist/payload list, not an
	// authorization source. Reading it as one would block every scan.
	if total == 0 || valid*2 < total {
		return nil, nil
	}
	return dedupe(hosts), nil
}

// parseTargetLine accepts URL / host[:port] / IP / CIDR lines.
func parseTargetLine(line string) (string, bool) {
	if i := strings.Index(line, "://"); i >= 0 {
		line = line[i+3:]
	}
	if h, _, ok := strings.Cut(line, "@"); ok {
		line = h
	}
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsAny(line, " \t") {
		return "", false
	}
	// A CIDR is a valid scope entry: keep the network form so the checker can
	// match it against scope rows instead of treating it as a single host.
	if i := strings.IndexByte(line, '/'); i > 0 {
		if net.ParseIP(line[:i]) != nil {
			if _, _, err := net.ParseCIDR(line); err == nil {
				return line, true
			}
		}
		line = line[:i] // URL path: keep the host part only
	}
	h := normalizeHost(line)
	if h == "" || looksLikeToken(h) || isFileName(h) {
		return "", false
	}
	if !strings.Contains(h, ".") && !strings.Contains(h, ":") {
		// A single-label host (docker-compose service name, or an intranet
		// name) is still a real target. Files reach this function only when
		// they were passed as a target list, so accept it when it looks like a
		// hostname rather than a path segment or payload.
		if !singleLabelHost(h) {
			return "", false
		}
	}
	return h, true
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// shellTokens is a deliberately small tokenizer: it splits on whitespace while
// honouring single/double quotes and backslash escapes. It is not a shell
// parser; it only needs to recover flag/value pairs reliably.
func shellTokens(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && quote != '\'':
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t' || r == '\n':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// singleLabelHost reports whether s looks like a bare hostname label.
func singleLabelHost(s string) bool {
	if len(s) < 2 || len(s) > 63 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0 && i < len(s)-1:
		default:
			return false
		}
	}
	return true
}
