package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/scopesync"
)

// taskScopeImport replaces a task's platform-sourced scope with a list parsed
// from the bug-bounty platform's own export.
//
// The operator supplies the payload (obtained from HackerOne / Bugcrowd /
// Intigriti). Handing the platform's authoritative list to the gate is the point:
// transcribing it by hand is how an engagement ends up authorised for a host
// nobody offered.
//
// Only source='platform' rows are replaced; anything typed in the UI ('manual')
// or derived from the goal ('goals') survives an import.
func (s *Server) taskScopeImport(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	as := s.m.Assets()
	if as == nil {
		writeErr(w, http.StatusServiceUnavailable, "asset store 未启用")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	var body struct {
		Platform  string          `json:"platform"`
		Payload   json.RawMessage `json:"payload"`
		SourceRef string          `json:"source_ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(body.Platform) == "" {
		writeErr(w, http.StatusBadRequest, "platform 必填（hackerone / bugcrowd / intigriti）")
		return
	}
	if len(body.Payload) == 0 {
		writeErr(w, http.StatusBadRequest, "payload 必填：粘贴平台导出的 scope JSON")
		return
	}

	rules, err := scopesync.Parse(body.Platform, body.Payload)
	if err != nil {
		// Parsing failures are reported, never downgraded to an empty list: an
		// empty scope silently makes the task unable to reach anything, which
		// looks like a malfunction rather than a bad import.
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	converted := make([]db.PlatformScopeRule, 0, len(rules))
	excluded := 0
	for _, r := range rules {
		if r.Excluded {
			excluded++
		}
		converted = append(converted, db.PlatformScopeRule{
			Kind: r.Kind, Value: r.Value, Excluded: r.Excluded, Note: r.Note,
		})
	}

	ref := strings.TrimSpace(body.SourceRef)
	if ref == "" {
		ref = fmt.Sprintf("%s@%s", strings.ToLower(body.Platform), time.Now().UTC().Format(time.RFC3339))
	}

	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskID <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return
	}
	added, removed, err := as.ReplacePlatformScope(taskID, converted, ref)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "导入失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"platform":   strings.ToLower(body.Platform),
		"source_ref": ref,
		"added":      added,
		"removed":    removed,
		"excluded":   excluded,
		"included":   len(converted) - excluded,
	})
}
