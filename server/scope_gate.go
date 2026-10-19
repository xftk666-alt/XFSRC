package server

import (
	"context"
	"log"
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
)

const defaultScopeTrustedSources = "manual,goals"

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
		hosts := guard.ExtractHosts(tool, input)
		// Targets can also live in a file (`cat targets.txt | httpx`,
		// `nuclei -l targets.txt`). Scan those too, and fail closed when the
		// list cannot be read.
		fileHosts, blockReason := guard.FileHosts(ctx, tool, input)
		if blockReason != "" {
			return hosts, blockReason
		}
		hosts = append(hosts, fileHosts...)
		if len(hosts) == 0 {
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
