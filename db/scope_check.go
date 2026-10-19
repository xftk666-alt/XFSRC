package db

import (
	"fmt"
	"net"
	"strings"
)

// DefaultTrustedScopeSources are the task_scope sources that may authorize a
// request. Only operator-confirmed scope (manual UI entry, or the goal
// decomposer working from the operator's own task description) is trusted.
// Rows written by planner/worker tools ('agent') and auto-added discovered
// assets ('auto') are deliberately NOT authoritative: otherwise an agent could
// widen its own authorization boundary.
var DefaultTrustedScopeSources = []string{"manual", "goals"}

type scopeEntry struct {
	kind   string
	domain string
	net    *net.IPNet
	value  string
}

// CheckTaskScopeHosts returns the subset of hosts NOT covered by the task's
// trusted scope. Fail-closed: no trusted rows, an empty task id, or a database
// error all yield every host as blocked.
func (d *DB) CheckTaskScopeHosts(taskID int64, hosts, trustedSources []string) ([]string, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	if taskID <= 0 {
		return append([]string(nil), hosts...), nil
	}
	if len(trustedSources) == 0 {
		trustedSources = DefaultTrustedScopeSources
	}
	placeholders := make([]string, len(trustedSources))
	args := []any{taskID}
	for i, s := range trustedSources {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, s)
	}
	rows, err := d.Query(`
SELECT kind, COALESCE(domain,''), COALESCE(net::text,''), COALESCE(value,''), COALESCE(company_id,0)
FROM task_scope
WHERE task_id=$1 AND source IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return append([]string(nil), hosts...), err
	}
	defer rows.Close()

	var entries []scopeEntry
	var companyIDs []int64
	for rows.Next() {
		var kind, domain, netText, value string
		var companyID int64
		if err := rows.Scan(&kind, &domain, &netText, &value, &companyID); err != nil {
			return append([]string(nil), hosts...), err
		}
		e := scopeEntry{kind: strings.ToLower(kind), domain: strings.ToLower(strings.TrimSuffix(domain, ".")), value: strings.TrimSpace(value)}
		if netText != "" {
			if _, n, err := net.ParseCIDR(netText); err == nil {
				e.net = n
			}
		}
		entries = append(entries, e)
		if companyID > 0 {
			companyIDs = append(companyIDs, companyID)
		}
	}
	if err := rows.Err(); err != nil {
		return append([]string(nil), hosts...), err
	}
	// Expand company rows through company_scope (domain/cidr rules only).
	for _, id := range companyIDs {
		crows, err := d.Query(`SELECT kind, COALESCE(domain,''), COALESCE(net::text,'') FROM company_scope WHERE company_id=$1`, id)
		if err != nil {
			continue
		}
		for crows.Next() {
			var kind, domain, netText string
			if err := crows.Scan(&kind, &domain, &netText); err != nil {
				continue
			}
			e := scopeEntry{kind: strings.ToLower(kind), domain: strings.ToLower(strings.TrimSuffix(domain, "."))}
			if netText != "" {
				if _, n, err := net.ParseCIDR(netText); err == nil {
					e.net = n
				}
			}
			entries = append(entries, e)
		}
		crows.Close()
	}

	if len(entries) == 0 {
		return append([]string(nil), hosts...), nil
	}
	var blocked []string
	for _, h := range hosts {
		if !hostInScope(h, entries) {
			blocked = append(blocked, h)
		}
	}
	return blocked, nil
}

// hostInScope reimplements the matching rules used by the operator-facing
// scope_check.py: CIDR containment first, then URL/domain/value matching.
func hostInScope(host string, entries []scopeEntry) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	ip := net.ParseIP(h)
	for _, e := range entries {
		if e.net != nil && ip != nil && e.net.Contains(ip) {
			return true
		}
		v := strings.ToLower(strings.TrimSuffix(e.value, "."))
		if v != "" {
			if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
				if vh := hostFromURL(v); vh != "" && hostMatches(h, vh, true) {
					return true
				}
			} else if _, n, err := net.ParseCIDR(v); err == nil {
				if ip != nil && n.Contains(ip) {
					return true
				}
			} else if hostMatches(h, v, true) {
				return true
			}
		}
		d := strings.TrimPrefix(e.domain, "*.")
		if d == "" {
			continue
		}
		switch e.kind {
		case "root_domain", "domain", "subdomain", "wildcard", "url":
			if hostMatches(h, d, true) {
				return true
			}
		default:
			if h == d {
				return true
			}
		}
	}
	return false
}

func hostMatches(host, scope string, allowSubdomains bool) bool {
	if host == scope {
		return true
	}
	return allowSubdomains && strings.HasSuffix(host, "."+scope)
}

func hostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(strings.Trim(raw, "[]"))
}
