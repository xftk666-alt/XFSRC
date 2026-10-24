package server

import (
	"context"
	"log"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

const (
	// settingScopeGateEnabled turns the pre-request authorization gate on/off.
	// Default ON: out-of-scope requests are the one irreversible mistake in
	// bug-bounty work, so the gate must be opt-out, not opt-in.
	settingScopeGateEnabled = "scope_gate_enabled"
	// settingScopeTrustedSources lists task_scope.source values that may
	// authorize a request. Agent-written ('agent') and auto-discovered ('auto')
	// rows are excluded by default so an agent cannot widen its own boundary.
	settingScopeTrustedSources = "scope_trusted_sources"
	// settingEgressInfraAllowlist lists hosts the platform itself needs when the
	// egress gate is enforced at the network layer: LLM endpoints, the self-update
	// source. Comma-separated, `*.example.com` matches subdomains. Without it,
	// forcing every outbound connection through the proxy would also block the
	// platform's own API calls.
	settingEgressInfraAllowlist = "egress_infra_allowlist"
)

const defaultScopeTrustedSources = "manual,goals,platform"

// scopeGateFor builds the guard.ScopeChecker for one task. The enabled flag and
// trusted sources are read per call so changing them in settings takes effect
// without rebuilding every agent.
func scopeGateFor(pg *db.DB, taskID int64) guard.ScopeChecker {
	return func(ctx context.Context, tool string, input []byte) ([]string, string) {
		if pg == nil || taskID <= 0 {
			return nil, ""
		}
		if !pg.GetBool(settingScopeGateEnabled, true) {
			return nil, ""
		}
		// A call whose targets cannot be determined is blocked, not allowed:
		// "extraction returned nothing" and "the extractor could not parse what
		// it saw" must not produce the same verdict.
		hosts, parseReason := guard.ExtractHostsChecked(tool, input)
		if parseReason != "" {
			return hosts, parseReason
		}
		// Targets can also live in a file (`cat targets.txt | httpx`,
		// `nuclei -l targets.txt`). Scan those too, and fail closed when the
		// list cannot be read.
		fileHosts, blockReason := guard.FileHosts(ctx, tool, input)
		if blockReason != "" {
			return hosts, blockReason
		}
		hosts = append(hosts, fileHosts...)
		// Targets can also live inside a script the call would run
		// (`python3 /tmp/recon.py`). The tool prompt recommends exactly that for
		// anything non-trivial, so leaving it unscanned made the gate optional.
		scriptHosts, scriptReason := guard.ScriptHosts(ctx, tool, input)
		if scriptReason != "" {
			return append(hosts, scriptHosts...), scriptReason
		}
		hosts = append(hosts, scriptHosts...)
		// A compiled binary executes code the gate cannot read. If the call named
		// no target of its own, its blast radius is unknowable, so deny it. When
		// the call does name targets, those are already in hosts and get the
		// normal scope check — the binary is assumed to act on them.
		if len(hosts) == 0 {
			if opaque := guard.OpaqueExecs(ctx, tool, input); len(opaque) > 0 {
				return nil, guard.OpaqueBlockReason(opaque)
			}
			return nil, ""
		}
		trusted := parseTrustedSources(pg)
		blocked, err := pg.CheckTaskScopeHosts(taskID, hosts, trusted)
		if err != nil {
			log.Printf("[scope] task %d 授权范围校验失败，按 fail-closed 阻止 %v: %v", taskID, hosts, err)
			return hosts, "授权范围校验失败（数据源不可用），已按 fail-closed 阻止执行"
		}
		if len(blocked) == 0 {
			return nil, ""
		}
		return blocked, "目标不在本任务授权范围内（task_scope，仅 " +
			strings.Join(trusted, "/") + " 来源可信）：" + strings.Join(blocked, ", ")
	}
}

func parseTrustedSources(pg *db.DB) []string {
	raw, _, err := pg.GetSetting(settingScopeTrustedSources)
	if err != nil || strings.TrimSpace(raw) == "" {
		raw = defaultScopeTrustedSources
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"manual", "goals"}
	}
	return out
}

// warnIfNoTaskScope records a visible activity when a task starts with an empty
// authorization boundary. It does NOT block: a task may legitimately make no
// network requests (analysis-only work, a wiring self-test). Blocking would
// break that, while staying silent leaves the operator with a task that
// mysteriously cannot reach anything — every request is refused at the proxy.
func (s *Server) warnIfNoTaskScope(task *Task) {
	if task == nil || s.m == nil || s.m.pg == nil {
		return
	}
	if !s.m.pg.GetBool(settingScopeGateEnabled, true) {
		return
	}
	id, err := strconv.ParseInt(task.ID, 10, 64)
	if err != nil || id <= 0 {
		return
	}
	n, err := s.m.pg.CountTrustedScopeRows(id, parseTrustedSources(s.m.pg))
	if err != nil {
		log.Printf("[scope] task %s 授权范围查询失败: %v", task.ID, err)
		return
	}
	if n == 0 {
		s.engine.emitActivity(task, db.Activity{
			Worker:  "system",
			Kind:    "text",
			Summary: "⚠ 本任务没有授权范围（task_scope 为空）：任何网络请求都会被出站闸门拒绝。请先录入 in-scope 目标。",
		})
	}
}

// infraHostAllowed reports whether host is on the platform's own allow-list.
// These are destinations the product must reach regardless of task scope (LLM
// providers, the self-update source), checked before the task scope so an
// operator does not have to add them to every engagement.
func infraHostAllowed(pg *db.DB, host string) bool {
	raw, _, err := pg.GetSetting(settingEgressInfraAllowlist)
	if err != nil || strings.TrimSpace(raw) == "" {
		return false
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, entry := range strings.Split(raw, ",") {
		e := strings.ToLower(strings.TrimSpace(entry))
		if e == "" {
			continue
		}
		if strings.HasPrefix(e, "*.") {
			suffix := strings.TrimPrefix(e, "*")
			if strings.HasSuffix(h, suffix) && len(h) > len(suffix) {
				return true
			}
			continue
		}
		if h == e {
			return true
		}
	}
	return false
}
