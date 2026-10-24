package db

import (
	"encoding/json"
	"testing"
)

// Archives written before task_scope gained `excluded` and `source_ref` carry
// neither key. The restore path builds rows through json_populate_recordset,
// which yields NULL for a missing field — and excluded is NOT NULL. Restoring an
// old archive therefore failed outright; this pins that it still restores, with
// the exclusion defaulting to false.
func TestRestoreLegacyTaskScopeWithoutNewColumns(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("legacy", "legacy", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	legacy := []map[string]any{{
		"task_id": task.ID,
		"kind":    "root_domain",
		"domain":  "legacy.example",
		"source":  "manual",
		"reason":  "旧归档",
		// deliberately no `excluded`, no `source_ref`
	}}
	raw, _ := json.Marshal(legacy)

	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := restoreTaskScopes(tx, raw); err != nil {
		t.Fatalf("legacy archive rejected: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	rows, err := d.Assets().ListTaskScope(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}
	if rows[0].Domain != "legacy.example" {
		t.Fatalf("domain = %q", rows[0].Domain)
	}
}
