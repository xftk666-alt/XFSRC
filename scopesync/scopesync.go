// Package scopesync parses the scope lists the bug-bounty platforms export into
// the rules this platform enforces.
//
// Why this exists: task scope was typed in by hand. On HackerOne, Bugcrowd and
// Intigriti the authoritative list is machine-readable, and transcribing it
// manually is itself a legal risk — one wrong character authorises a host nobody
// offered, or drops one that was in scope. Parsing the export removes that step.
//
// Only parsing lives here. Fetching is deliberately NOT implemented: it needs a
// per-platform API token and an endpoint contract that must be verified against
// the live API, and a guessed URL is worse than none. Feed Parse the JSON the
// operator obtained from the platform.
package scopesync

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// Rule is one authorization entry, independent of the platform it came from.
type Rule struct {
	// Kind is one of: root_domain, subdomain, ip, cidr, keyword.
	Kind string
	// Value is the normalised host, network or keyword.
	Value string
	// Excluded marks an explicit out-of-scope entry. Exclusions win over
	// inclusions when the gate decides.
	Excluded bool
	// Note carries the platform's own instruction text, for the audit trail.
	Note string
}

// Platform identifiers accepted by Parse.
const (
	HackerOne = "hackerone"
	Bugcrowd  = "bugcrowd"
	Intigriti = "intigriti"
)

// Parse dispatches on platform name. Unknown platforms are an error rather than
// a guess: silently parsing the wrong shape would produce an empty scope, and an
// empty scope looks like "nothing is authorised" only after the fact.
func Parse(platform string, payload []byte) ([]Rule, error) {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case HackerOne:
		return ParseHackerOne(payload)
	case Bugcrowd:
		return ParseBugcrowd(payload)
	case Intigriti:
		return ParseIntigriti(payload)
	default:
		return nil, fmt.Errorf("未知平台 %q（支持：hackerone、bugcrowd、intigriti）", platform)
	}
}

// --- HackerOne -------------------------------------------------------------
//
// GET /v1/hacker_programs/{handle}/structured_scopes returns
//
//	{"data":[{"attributes":{"asset_identifier":"*.example.com",
//	                         "asset_type":"WILDCARD",
//	                         "eligible_for_submission":true,
//	                         "instruction":"..."}}]}
//
// eligible_for_submission=false is HackerOne's "out of scope" marker.
func ParseHackerOne(payload []byte) ([]Rule, error) {
	var doc struct {
		Data []struct {
			Attributes struct {
				Identifier  string `json:"asset_identifier"`
				Type        string `json:"asset_type"`
				Eligible    *bool  `json:"eligible_for_submission"`
				Instruction string `json:"instruction"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("hackerone: %w", err)
	}
	if len(doc.Data) == 0 {
		return nil, fmt.Errorf("hackerone: 响应里没有 scope 条目（检查程序 handle 与权限）")
	}
	var out []Rule
	for _, d := range doc.Data {
		a := d.Attributes
		inScope := a.Eligible == nil || *a.Eligible
		r, err := classify(a.Identifier, a.Type, !inScope, a.Instruction)
		if err != nil {
			// A single unparseable row must not silently disappear: that would
			// shrink the authorised set without anyone noticing.
			return nil, fmt.Errorf("hackerone: %q: %w", a.Identifier, err)
		}
		out = append(out, r)
	}
	return dedupe(out), nil
}

// --- Bugcrowd --------------------------------------------------------------
//
// Bugcrowd's scope export lists targets with a category and an in/out marker.
// Field names vary between the API and the UI export, so several aliases are
// accepted; anything unrecognised is an error, never a silent skip.
func ParseBugcrowd(payload []byte) ([]Rule, error) {
	var doc struct {
		Scope []map[string]any `json:"scope"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("bugcrowd: %w", err)
	}
	if len(doc.Scope) == 0 {
		return nil, fmt.Errorf("bugcrowd: 响应里没有 scope 条目")
	}
	var out []Rule
	for _, item := range doc.Scope {
		target := firstString(item, "target", "name", "asset", "endpoint", "uri")
		if target == "" {
			return nil, fmt.Errorf("bugcrowd: scope 条目缺少 target/name 字段: %v", item)
		}
		inScope := true
		if v, ok := firstBool(item, "in_scope", "inScope", "eligible_for_submission"); ok {
			inScope = v
		}
		kind := firstString(item, "category", "type", "asset_type")
		r, err := classify(target, kind, !inScope, firstString(item, "description", "instruction"))
		if err != nil {
			return nil, fmt.Errorf("bugcrowd: %q: %w", target, err)
		}
		out = append(out, r)
	}
	return dedupe(out), nil
}

// --- Intigriti -------------------------------------------------------------
//
// Intigriti's program scope is a list of endpoints with a type and an
// in-scope boolean. Same alias policy as Bugcrowd.
func ParseIntigriti(payload []byte) ([]Rule, error) {
	var doc struct {
		Scope []map[string]any `json:"scope"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("intigriti: %w", err)
	}
	if len(doc.Scope) == 0 {
		return nil, fmt.Errorf("intigriti: 响应里没有 scope 条目")
	}
	var out []Rule
	for _, item := range doc.Scope {
		target := firstString(item, "endpoint", "target", "name", "asset")
		if target == "" {
			return nil, fmt.Errorf("intigriti: scope 条目缺少 endpoint 字段: %v", item)
		}
		inScope := true
		if v, ok := firstBool(item, "inScope", "in_scope", "eligible"); ok {
			inScope = v
		}
		r, err := classify(target, firstString(item, "type", "category"), !inScope, firstString(item, "description", "instruction"))
		if err != nil {
			return nil, fmt.Errorf("intigriti: %q: %w", target, err)
		}
		out = append(out, r)
	}
	return dedupe(out), nil
}

// classify turns a platform asset into a rule. assetType is advisory: the value
// itself decides ip/cidr, and the type only disambiguates "is a bare domain the
// whole tree or one host".
//
// A wildcard or an explicit domain type authorises the domain tree
// (root_domain). Anything else is treated as one exact host, because widening an
// exact host to its subdomains would authorise targets the program never
// offered.
func classify(raw, assetType string, excluded bool, note string) (Rule, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return Rule{}, fmt.Errorf("空值")
	}
	t := strings.ToUpper(strings.TrimSpace(assetType))

	// URL → its host.
	if strings.HasPrefix(strings.ToLower(v), "http://") || strings.HasPrefix(strings.ToLower(v), "https://") {
		h := hostFromURL(v)
		if h == "" {
			return Rule{}, fmt.Errorf("无法从 URL 解析主机")
		}
		v = h
		t = "URL"
	}

	v = strings.TrimSuffix(strings.TrimSpace(v), ".")
	if _, ipnet, err := net.ParseCIDR(v); err == nil {
		return Rule{Kind: "cidr", Value: ipnet.String(), Excluded: excluded, Note: note}, nil
	}
	if ip := net.ParseIP(v); ip != nil {
		return Rule{Kind: "ip", Value: ip.String(), Excluded: excluded, Note: note}, nil
	}

	wildcard := strings.HasPrefix(v, "*.")
	v = strings.TrimPrefix(v, "*.")
	v = strings.ToLower(v)
	if v == "" || strings.ContainsAny(v, " /") {
		return Rule{}, fmt.Errorf("不是合法的主机或网络")
	}
	if !strings.Contains(v, ".") {
		// A bare keyword (e.g. a program-specific string) is not a host; keeping
		// it as a keyword avoids silently treating it as a domain.
		if t == "KEYWORD" || t == "OTHER" {
			return Rule{Kind: "keyword", Value: v, Excluded: excluded, Note: note}, nil
		}
		return Rule{}, fmt.Errorf("主机缺少点号，且未标注为 keyword")
	}
	if wildcard || t == "WILDCARD" || t == "DOMAIN" || t == "ROOT_DOMAIN" {
		return Rule{Kind: "root_domain", Value: v, Excluded: excluded, Note: note}, nil
	}
	return Rule{Kind: "subdomain", Value: v, Excluded: excluded, Note: note}, nil
}

func hostFromURL(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.ToLower(strings.Trim(s, "[]"))
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

func firstBool(m map[string]any, keys ...string) (bool, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if b, ok := v.(bool); ok {
				return b, true
			}
		}
	}
	return false, false
}

// dedupe drops exact repeats. Later entries win, so an out-of-scope row that
// repeats an in-scope target is not lost.
func dedupe(in []Rule) []Rule {
	type key struct {
		kind, value string
		excluded    bool
	}
	seen := map[key]bool{}
	out := make([]Rule, 0, len(in))
	for _, r := range in {
		k := key{r.Kind, r.Value, r.Excluded}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}
