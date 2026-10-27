package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	// wget's short form of --input-file. Tool-scoped on purpose: `curl -i` means
	// "include headers", so an unrestricted -i would read the URL after it as a
	// target list and fail closed on legitimate curl calls.
	"-i": {"wget": true},
	"-input":       nil,
	"-inputlist":   nil,
	"-targets":     nil,
	"-target-file": nil,
	"--url-file":   nil,
	// GNU-style long forms. These were missing, so `--targets=FILE` never
	// registered as a target list at all.
	"--list":        {"httpx": true, "nuclei": true, "katana": true, "naabu": true},
	"--targets":     nil,
	"--target":      nil,
	"--target-file": nil,
	"--input":       nil,
	"--inputlist":   nil,
	"--input-file":  nil,
	"--urls":        nil,
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
	return targetFilesInDepth(command, 0)
}

// nestedShells are interpreters whose `-c` argument is a script to run. Without
// re-parsing that argument the whole sub-command stays one opaque token, so
// `sh -c "nuclei -l targets.txt"` never reached the target-list reader.
var nestedShells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true,
}

// substitutionReaders are commands whose operand is a file path, used when they
// appear inside `$(...)`: `curl "$(cat targets.txt)"`.
var substitutionReaders = map[string]bool{
	"cat": true, "tac": true, "echo": true, "printf": true, "head": true, "tail": true,
}

func targetFilesInDepth(command string, depth int) []string {
	if depth > 4 {
		return nil
	}
	tokens := shellTokens(command)
	var out []string
	for i, tok := range tokens {
		// Nested shell: `sh -c "<script>"`. The quoted script is a single token,
		// so it has to be re-parsed or every target inside it is invisible.
		if strings.EqualFold(tok, "-c") && i > 0 && i+1 < len(tokens) {
			if nestedShells[strings.ToLower(filepath.Base(tokens[i-1]))] {
				out = append(out, targetFilesInDepth(tokens[i+1], depth+1)...)
				continue
			}
		}
		// Command substitution inside a token: `$(cat FILE)`, `` `cat FILE` ``.
		// The substituted text is what the tool actually receives.
		for _, sub := range substitutionCommands(tok) {
			out = append(out, targetFilesInDepth(sub, depth+1)...)
			if p := substitutionReaderFile(sub); p != "" {
				out = append(out, p)
			}
		}
		name := strings.ToLower(tok)
		// Attached forms: `-l=targets.txt`, `--targets=targets.txt`, and GNU short
		// `-ltargets.txt`. Without these the flag never matched, so the file was
		// never read and the call was allowed with no hosts checked.
		flag, value, hasValue := splitAttachedFlag(tok)
		if tools, ok := targetFileFlag[flag]; ok {
			if tools != nil && !toolMatches(tokens, tools) {
				continue
			}
			if hasValue {
				if p := cleanPathToken(value); p != "" && !strings.Contains(p, "://") {
					out = append(out, p)
				}
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
	}
	// `< targets.txt` / `0< targets.txt`. The tokenizer treats '<' as a word
	// separator, so the operator is gone by now — scan the raw text instead.
	out = append(out, redirectSources(command)...)
	// `cmd > out.txt; cat out.txt` is a normal capture-and-read pattern: the file
	// is this command's own output, so it cannot be a pre-existing target list and
	// reading it at gate time fails closed for no reason.
	out = removeAll(out, redirectDestinations(command))
	return dedupe(out)
}

// redirectDestinations returns the files written by `> FILE` / `>> FILE`.
func redirectDestinations(command string) []string {
	var out []string
	for i := 0; i < len(command); i++ {
		if command[i] != '>' {
			continue
		}
		// Skip `2>&1`, `>&2` and here-strings.
		if i+1 < len(command) && (command[i+1] == '&' || command[i+1] == '>' && i+2 < len(command) && command[i+2] == '&') {
			continue
		}
		j := i + 1
		if j < len(command) && command[j] == '>' {
			j++
		}
		for j < len(command) && (command[j] == ' ' || command[j] == '\t') {
			j++
		}
		end := strings.IndexAny(command[j:], " \t\n|&;()<>")
		if end < 0 {
			end = len(command) - j
		}
		if p := cleanPathToken(command[j : j+end]); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// removeAll drops every element of in that appears in drop.
func removeAll(in, drop []string) []string {
	if len(drop) == 0 {
		return in
	}
	skip := make(map[string]bool, len(drop))
	for _, d := range drop {
		skip[d] = true
	}
	out := in[:0]
	for _, v := range in {
		if !skip[v] {
			out = append(out, v)
		}
	}
	return out
}

// substitutionCommands returns the inner command of every `$(...)` and
// `` `...` `` span in tok. Deeper nesting is handled by the depth limit in
// targetFilesInDepth.
func substitutionCommands(tok string) []string {
	var out []string
	for i := 0; i < len(tok); i++ {
		if tok[i] == '$' && i+1 < len(tok) && tok[i+1] == '(' {
			depth := 1
			for j := i + 2; j < len(tok); j++ {
				switch tok[j] {
				case '(':
					depth++
				case ')':
					depth--
					if depth == 0 {
						if inner := strings.TrimSpace(tok[i+2 : j]); inner != "" {
							out = append(out, inner)
						}
					}
				}
				if depth == 0 {
					break
				}
			}
			continue
		}
		if tok[i] == '`' {
			if j := strings.IndexByte(tok[i+1:], '`'); j >= 0 {
				if inner := strings.TrimSpace(tok[i+1 : i+1+j]); inner != "" {
					out = append(out, inner)
				}
				i += j + 1
			}
		}
	}
	return out
}

// substitutionReaderFile returns the file operand when the substituted command is
// a plain reader (`cat FILE`, `echo FILE`). `echo` is not a target-list flag, so
// the recursive pass alone would not surface the file.
func substitutionReaderFile(cmd string) string {
	tokens := shellTokens(cmd)
	if len(tokens) < 2 {
		return ""
	}
	if !substitutionReaders[strings.ToLower(filepath.Base(tokens[0]))] {
		return ""
	}
	for _, tok := range tokens[1:] {
		if strings.HasPrefix(tok, "-") {
			continue
		}
		p := cleanPathToken(tok)
		if p == "" || strings.Contains(p, "://") {
			continue
		}
		if looksLikePath(p) {
			return p
		}
	}
	return ""
}

// redirectSources finds `FILE` in `< FILE` and `0< FILE`.
func redirectSources(command string) []string {
	var out []string
	for i := 0; i < len(command); i++ {
		if command[i] != '<' {
			continue
		}
		// Skip `<<` (heredoc) — its body is not a target list.
		if i+1 < len(command) && command[i+1] == '<' {
			i++
			continue
		}
		rest := command[i+1:]
		rest = strings.TrimLeft(rest, " \t")
		end := strings.IndexAny(rest, " \t\n|&;()<>")
		if end < 0 {
			end = len(rest)
		}
		if p := cleanPathToken(rest[:end]); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitAttachedFlag splits `--targets=x`, `-l=x` and `-lx` into ("--targets", "x", true)
// / ("-l", "x", true). A token without an attached value returns (tok, "", false).
func splitAttachedFlag(tok string) (flag, value string, hasValue bool) {
	if !strings.HasPrefix(tok, "-") {
		return tok, "", false
	}
	if eq := strings.IndexByte(tok, '='); eq > 0 {
		return strings.ToLower(tok[:eq]), tok[eq+1:], true
	}
	lower := strings.ToLower(tok)
	// An exact flag name never carries an attached value: `-il` is nmap's
	// target-list flag, not `-i` with the value "l".
	if _, ok := targetFileFlag[lower]; ok {
		return lower, "", false
	}
	// GNU short option with an attached value (`-ltargets.txt`). Longest match
	// first so the result does not depend on map iteration order.
	best := ""
	for known := range targetFileFlag {
		if len(known) == 2 && len(tok) > 2 && strings.HasPrefix(lower, known) && len(known) > len(best) {
			best = known
		}
	}
	if best != "" {
		return best, tok[len(best):], true
	}
	return lower, "", false
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
	// A substitution is resolved by targetFilesInDepth, which reads the file it
	// expands to. Returning the raw `$(cat x)` text here would make the caller
	// stat a path that does not exist and fail closed on a legitimate call.
	if strings.Contains(tok, "$(") || strings.Contains(tok, "`") || strings.Contains(tok, "${") {
		return ""
	}
	return tok
}

func looksLikePath(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") {
		return true
	}
	if strings.Contains(p, "/") {
		return true
	}
	// An extensionless name ("targets", "hosts") has no Ext at all; slicing
	// Ext(p)[1:] there panicked, and `cat targets | httpx` is a normal way to
	// feed a target list.
	ext := filepath.Ext(p)
	if ext == "" {
		return true
	}
	return hostOnlyFiles[strings.ToLower(ext[1:])]
}

// readTargetHosts reads one target list and returns the hosts it contains.
//
// The file was named as a target list, so anything it cannot be read as is a
// fail-closed condition, not "no targets here". Returning (nil, nil) for a
// directory, an oversized file, or a non-regular file let an agent point the
// gate at something it would not read while the tool still scanned the real
// hosts.
func readTargetHosts(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		// FIFOs, sockets and device nodes would block or stream forever inside
		// the authorization path (`nuclei -l /dev/zero`).
		return nil, fmt.Errorf("不是普通文件（%s）", fi.Mode().Type())
	}
	if fi.Size() > maxTargetFileBytes {
		return nil, fmt.Errorf("超过 %d 字节上限", maxTargetFileBytes)
	}
	// Read through a LimitReader as well: Size() is advisory and a growing file
	// would otherwise be buffered whole.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTargetFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxTargetFileBytes {
		return nil, fmt.Errorf("读取过程中超过 %d 字节上限", maxTargetFileBytes)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxTargetFileLines {
		// Silently truncating let an agent push out-of-scope hosts past the cap.
		return nil, fmt.Errorf("超过 %d 行上限", maxTargetFileLines)
	}
	var hosts []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h, ok := parseTargetLine(line)
		if !ok {
			// A line the parser does not understand could be a host it failed to
			// read; skipping it silently is how padding with junk hid targets.
			return nil, fmt.Errorf("无法解析的行：%q", truncateForError(line))
		}
		hosts = append(hosts, h)
	}
	return dedupe(hosts), nil
}

// truncateForError keeps error text bounded when echoing an agent-supplied line.
func truncateForError(s string) string {
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// parseTargetLine accepts URL / host[:port] / IP / CIDR lines.
func parseTargetLine(line string) (string, bool) {
	// A URL's authority ends at the first path/query/fragment delimiter, and
	// userinfo only means something inside that authority. Applying the '@' split
	// to the whole line let a path or query decide the "host":
	// `https://evil.example/?to=@in-scope.example` was read as in-scope.example
	// while the tool actually fetched evil.example.
	//
	// Lines without a scheme are not cut at '/', because a bare CIDR
	// (`10.0.0.0/8`) uses the same character.
	if i := strings.Index(line, "://"); i >= 0 {
		rest := line[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		line = rest
	}
	// Keep the part AFTER the last '@' inside the authority: that is the host.
	if at := strings.LastIndexByte(line, '@'); at >= 0 {
		line = line[at+1:]
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
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
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
			flush()
		// Shell metacharacters terminate a word. Without this, `cat targets.txt|httpx`
		// produced the single token "targets.txt|httpx", which cleanPathToken then
		// rejected — so the target list was never read and the gate saw no hosts.
		case r == '|' || r == ';' || r == '&' || r == '(' || r == ')' || r == '>' || r == '<':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
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
