package db

import (
	"fmt"
	"net"
	"strings"
)

// DefaultTrustedScopeSources are the task_scope sources that may authorize a
// request. Only operator-confirmed scope is trusted: manual UI entry, the goal
// decomposer working from the operator's own task description, and a list
// imported from the bug-bounty platform ('platform') through the authenticated
// import endpoint.
//
// Rows written by planner/worker tools ('agent') and auto-added discovered
// assets ('auto') are deliberately NOT authoritative: otherwise an agent could
// widen its own authorization boundary.
var DefaultTrustedScopeSources = []string{"manual", "goals", "platform"}

type scopeEntry struct {
	kind   string
	domain string
	net    *net.IPNet
	value  string
	// excluded marks an explicit "out of scope" rule. Exclusions are checked
	// first and win over every inclusion: a platform that lists example.com and
	// also lists admin.example.com as out of scope means exactly that.
	excluded bool
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
SELECT kind, COALESCE(domain,''), COALESCE(net::text,''), COALESCE(value,''), COALESCE(company_id,0), excluded
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
		var excluded bool
		if err := rows.Scan(&kind, &domain, &netText, &value, &companyID, &excluded); err != nil {
			return append([]string(nil), hosts...), err
		}
		e := scopeEntry{kind: strings.ToLower(kind), domain: strings.ToLower(strings.TrimSuffix(domain, ".")), value: strings.TrimSpace(value), excluded: excluded}
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
	// Expand company rows through company_scope. Only rules written by a trusted
	// source count: a model-driven tool (add_company_scope) or an automated import
	// can add rows to a company, and expanding those would let an agent widen the
	// authorization boundary of every task that references the company.
	cPlaceholders := make([]string, len(trustedSources))
	cArgs := make([]any, 0, len(trustedSources)+1)
	for i, src := range trustedSources {
		cPlaceholders[i] = fmt.Sprintf("$%d", i+2)
		cArgs = append(cArgs, src)
	}
	for _, id := range companyIDs {
		crows, err := d.Query(`SELECT kind, COALESCE(domain,''), COALESCE(net::text,'')
FROM company_scope WHERE company_id=$1 AND source IN (`+strings.Join(cPlaceholders, ",")+`)`, append([]any{id}, cArgs...)...)
		if err != nil {
			continue
		}
		for crows.Next() {
			var kind, domain, netText string
			if err := crows.Scan(&kind, &domain, &netText); err != nil {
				continue
			}
			kind = strings.ToLower(kind)
			if kind == "domain" {
				// company_scope 'domain' means "this company owns the domain and its
				// subdomains" (that is also how attribution works), so expand it as a
				// root-domain rule rather than an exact-host one.
				kind = "root_domain"
			}
			e := scopeEntry{kind: kind, domain: strings.ToLower(strings.TrimSuffix(domain, "."))}
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
// scope_check.py: CIDR containment first, then URL/domain/value matching, with
// explicit out-of-scope rules taking precedence over any in-scope rule.
func hostInScope(host string, entries []scopeEntry) bool {
	if hostMatchesEntries(host, entries, true) {
		return false
	}
	return hostMatchesEntries(host, entries, false)
}

// hostMatchesEntries reports whether host matches an entry of the given kind
// (excluded or not).
func hostMatchesEntries(host string, entries []scopeEntry, excluded bool) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	ip := net.ParseIP(h)
	for _, e := range entries {
		if e.excluded != excluded {
			continue
		}
		if e.net != nil && ip != nil && e.net.Contains(ip) {
			return true
		}
		// icp/keyword are coverage hints, not network targets: an ICP filing number
		// or a company keyword must never authorize a hostname (a keyword such as
		// "acme" would otherwise authorize "evil.acme").
		if e.kind == "icp" || e.kind == "keyword" {
			continue
		}
		v := strings.ToLower(strings.TrimSuffix(e.value, "."))
		if v != "" {
			if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
				if vh := hostFromURL(v); vh != "" && vh == h {
					return true
				}
			} else if _, n, err := net.ParseCIDR(v); err == nil {
				if ip != nil && n.Contains(ip) {
					return true
				}
			} else if v == h {
				return true
			}
		}
		d := strings.TrimPrefix(e.domain, "*.")
		if d == "" {
			continue
		}
		// Subdomain granularity is exact. A `subdomain` row for api.example.com
		// must NOT authorize evil.api.example.com: the operator registered one
		// host, and suffix matching silently widened it to every descendant.
		// Only an explicit root-domain/wildcard row covers subdomains.
		switch e.kind {
		case "root_domain", "wildcard":
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

// AllowedHostsAcrossActiveTasks reports whether host is authorized by any task
// that is currently running. The recording proxy is a single global listener and
// cannot tell which task a request came from, so the egress allow-list is the
// union of every active task's trusted scope. A host nobody authorized is
// refused at the proxy, which is the only enforcement point a compiled binary
// or an obfuscated command line cannot step around.
//
// Fail-closed: a database error returns false.
func (d *DB) AllowedHostsAcrossActiveTasks(host string, trustedSources []string) (bool, error) {
	if host == "" {
		return false, nil
	}
	if len(trustedSources) == 0 {
		trustedSources = DefaultTrustedScopeSources
	}
	ph := make([]string, len(trustedSources))
	args := make([]any, 0, len(trustedSources)+1)
	for i, s := range trustedSources {
		ph[i] = fmt.Sprintf("$%d", i+1)
		args = append(args, s)
	}
	// Only tasks that can still make requests: a done/archived task's scope must
	// not keep a host reachable forever.
	rows, err := d.Query(`
SELECT s.kind, COALESCE(s.domain,''), COALESCE(s.net::text,''), COALESCE(s.value,''), COALESCE(s.company_id,0), s.excluded
FROM task_scope s
JOIN tasks t ON t.id = s.task_id
WHERE s.source IN (`+strings.Join(ph, ",")+`)
  AND t.deleted_at IS NULL
  AND COALESCE(t.status,'') NOT IN ('done','failed','timeout','archived')`, args...)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var entries []scopeEntry
	var companyIDs []int64
	for rows.Next() {
		var kind, domain, netText, value string
		var companyID int64
		var excluded bool
		if err := rows.Scan(&kind, &domain, &netText, &value, &companyID, &excluded); err != nil {
			return false, err
		}
		e := scopeEntry{kind: strings.ToLower(kind), domain: strings.ToLower(strings.TrimSuffix(domain, ".")), value: strings.TrimSpace(value), excluded: excluded}
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
		return false, err
	}
	cph := make([]string, len(trustedSources))
	cargs := make([]any, 0, len(trustedSources)+1)
	for i, s := range trustedSources {
		cph[i] = fmt.Sprintf("$%d", i+2)
		cargs = append(cargs, s)
	}
	for _, id := range companyIDs {
		crows, err := d.Query(`SELECT kind, COALESCE(domain,''), COALESCE(net::text,'')
FROM company_scope WHERE company_id=$1 AND source IN (`+strings.Join(cph, ",")+`)`, append([]any{id}, cargs...)...)
		if err != nil {
			continue
		}
		for crows.Next() {
			var kind, domain, netText string
			if err := crows.Scan(&kind, &domain, &netText); err != nil {
				continue
			}
			kind = strings.ToLower(kind)
			if kind == "domain" {
				kind = "root_domain"
			}
			e := scopeEntry{kind: kind, domain: strings.ToLower(strings.TrimSuffix(domain, "."))}
			if netText != "" {
				if _, n, err := net.ParseCIDR(netText); err == nil {
					e.net = n
				}
			}
			entries = append(entries, e)
		}
		crows.Close()
	}
	return hostInScope(host, entries), nil
}

// CountTrustedScopeRows reports how many trusted scope rows a task has, without
// expanding company rows. Used to refuse starting a task whose authorization
// boundary is empty: such a task can contact nothing, and letting it run only
// produces a stream of blocked calls.
func (d *DB) CountTrustedScopeRows(taskID int64, trustedSources []string) (int, error) {
	if taskID <= 0 {
		return 0, nil
	}
	if len(trustedSources) == 0 {
		trustedSources = DefaultTrustedScopeSources
	}
	ph := make([]string, len(trustedSources))
	args := make([]any, 0, len(trustedSources)+1)
	args = append(args, taskID)
	for i, s := range trustedSources {
		ph[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, s)
	}
	var n int
	err := d.QueryRow(`SELECT count(*) FROM task_scope WHERE task_id=$1 AND source IN (`+
		strings.Join(ph, ",")+`)`, args...).Scan(&n)
	return n, err
}
