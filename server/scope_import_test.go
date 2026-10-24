package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// The import endpoint is the only path that writes source='platform' rows, and
// those rows are trusted by the gate. A regression here would either authorise
// nothing (silent empty scope) or authorise the wrong tree.
func TestTaskScopeImportEndpoint(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("manager unavailable (%v)", err)
	}
	defer m.Close()
	task, err := m.CreateTask("import", "import", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	s := &Server{m: m}
	body := map[string]any{
		"platform": "hackerone",
		"payload": json.RawMessage(`{"data":[
			{"attributes":{"asset_identifier":"*.example.com","asset_type":"WILDCARD","eligible_for_submission":true}},
			{"attributes":{"asset_identifier":"admin.example.com","asset_type":"URL","eligible_for_submission":false}}
		]}`),
		"source_ref": "hackerone/acme@2026-10-24",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/tasks/"+task.ID+"/scope/import", bytes.NewReader(raw))
	req.SetPathValue("id", task.ID)
	rec := httptest.NewRecorder()
	s.taskScopeImport(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	var out struct {
		Added    int `json:"added"`
		Excluded int `json:"excluded"`
		Included int `json:"included"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Added != 2 || out.Excluded != 1 || out.Included != 1 {
		t.Fatalf("counts = %+v, want added=2 excluded=1 included=1", out)
	}

	// The imported list must now govern the gate: included tree honoured,
	// explicit exclusion refused.
	check := scopeGateFor(m.pg, mustInt64(t, task.ID))
	blocked, _ := check(t.Context(), "Bash", []byte(`{"command":"curl https://api.example.com"}`))
	if len(blocked) != 0 {
		t.Errorf("imported root domain should authorise api.example.com, blocked=%v", blocked)
	}
	blocked, reason := check(t.Context(), "Bash", []byte(`{"command":"curl https://admin.example.com"}`))
	if len(blocked) == 0 {
		t.Errorf("imported exclusion must block admin.example.com (reason=%q)", reason)
	}
}

// Bad payloads are rejected rather than turned into an empty scope.
func TestTaskScopeImportRejectsBadPayload(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("manager unavailable (%v)", err)
	}
	defer m.Close()
	task, err := m.CreateTask("import-bad", "import-bad", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	s := &Server{m: m}
	for _, body := range []string{
		`{"platform":"hackerone","payload":{"data":[]}}`,
		`{"platform":"nope","payload":{"data":[]}}`,
		`{"payload":{"data":[]}}`,
	} {
		req := httptest.NewRequest("POST", "/x", bytes.NewReader([]byte(body)))
		req.SetPathValue("id", task.ID)
		rec := httptest.NewRecorder()
		s.taskScopeImport(rec, req)
		if rec.Code != 400 {
			t.Errorf("body %s: status = %d, want 400", body, rec.Code)
		}
	}
}

func mustInt64(t *testing.T, s string) int64 {
	t.Helper()
	var v int64
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("not numeric: %q", s)
		}
		v = v*10 + int64(c-'0')
	}
	return v
}
