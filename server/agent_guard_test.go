package server

import (
	"context"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// Every agent that can run Bash/WebFetch must carry the task's guard. The
// authorization gate used to be attached to workers only, which made the scope
// boundary bypassable from the planner and the main agent — both of which read
// target-controlled content and run with ModeBypass.
func TestTaskAgentsCarryTheAuthorizationGuard(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	task, err := m.CreateTaskWithOptions("guard wiring", "smoke", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	rt := m.ResolveTask(task.ID)
	if rt == nil {
		t.Fatal("task not registered")
	}
	bundle := s.agentsForTask(rt)
	if bundle == nil || bundle.pl == nil || bundle.main == nil || bundle.wk == nil {
		t.Fatalf("incomplete agent bundle: %+v", bundle)
	}
	if bundle.pl.Hooks() == nil {
		t.Error("planner has no guard: out-of-scope requests and destructive commands reach it unguarded")
	}
	if bundle.main.Hooks() == nil {
		t.Error("main agent has no guard")
	}
}

// A guard-less task must not panic the resolver (e.g. tasks created by tests or
// restored before the manager wires a guard).
func TestTaskAgentsTolerateMissingGuard(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	task, err := m.CreateTaskWithOptions("guard wiring nil", "smoke", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })

	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	rt := m.ResolveTask(task.ID)
	if rt == nil {
		t.Fatal("task not registered")
	}
	rt.Guard = nil
	bundle := s.agentsForTask(rt)
	if bundle == nil || bundle.pl == nil {
		t.Fatal("resolver failed without a guard")
	}
	if bundle.pl.Hooks() != nil {
		t.Error("planner invented a guard")
	}
}
