package db

import (
	"testing"
)

func TestCheckTaskScopeHosts(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateTaskWithOptions("scope gate fixture", "read scope", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	as := d.Assets()
	add := func(kind, value, source string) {
		t.Helper()
		if _, err := as.AddAgentScope(task.ID, kind, value, "fixture", source); err != nil {
			t.Fatalf("add scope %s=%s: %v", kind, value, err)
		}
	}
	add("root_domain", "example.com", "manual")
	add("cidr", "10.0.0.0/24", "goals")
	// These must never authorize: an agent widening its own boundary, and an
	// auto-added discovered asset.
	add("root_domain", "evil.example", "agent")
	add("root_domain", "auto.example", "auto")

	blocked, err := d.CheckTaskScopeHosts(task.ID, []string{
		"api.example.com", // manual root domain covers subdomains
		"10.0.0.7",        // goals cidr covers the address
		"evil.example",    // agent-written: not trusted
		"auto.example",    // auto-written: not trusted
		"out.example.net", // never registered
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"evil.example": true, "auto.example": true, "out.example.net": true}
	if len(blocked) != len(want) {
		t.Fatalf("blocked=%v, want %v", blocked, want)
	}
	for _, h := range blocked {
		if !want[h] {
			t.Fatalf("unexpected block %q (all: %v)", h, blocked)
		}
	}
}

func TestCheckTaskScopeHostsFailClosed(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateTaskWithOptions("scope gate empty", "no scope", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	blocked, err := d.CheckTaskScopeHosts(task.ID, []string{"example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 1 {
		t.Fatalf("empty scope must fail closed, blocked=%v", blocked)
	}
}

// A `subdomain` row authorizes exactly that host. It must not silently widen to
// every descendant: the operator registered one host, and suffix matching used to
// make api.example.com cover evil.api.example.com.
func TestTaskScopeSubdomainIsExact(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateTaskWithOptions("scope subdomain", "exact", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	as := d.Assets()
	if _, err := as.AddAgentScope(task.ID, "subdomain", "api.example.com", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := as.AddAgentScope(task.ID, "root_domain", "root.example", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}

	blocked, err := d.CheckTaskScopeHosts(task.ID, []string{
		"api.example.com",      // registered exactly
		"evil.api.example.com", // descendant of an exact row: NOT covered
		"a.root.example",       // root_domain covers subdomains
		"root.example",         // and itself
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 1 || blocked[0] != "evil.api.example.com" {
		t.Fatalf("blocked = %v, want [evil.api.example.com]", blocked)
	}
}

// icp / keyword are coverage hints, never network authorization: a keyword such
// as "acme" must not authorize evil.acme.
func TestTaskScopeIcpAndKeywordNeverAuthorize(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, err := d.CreateTaskWithOptions("scope keyword", "hint only", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	as := d.Assets()
	if _, err := as.AddAgentScope(task.ID, "keyword", "acme", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := as.AddAgentScope(task.ID, "icp", "京ICP备12345678号", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	blocked, err := d.CheckTaskScopeHosts(task.ID, []string{"acme", "evil.acme", "京ICP备12345678号"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 3 {
		t.Fatalf("blocked = %v, want every host (hints must not authorize)", blocked)
	}
}

// Company scope feeds every task referencing that company, so only rules written
// by a trusted source may authorize — otherwise an agent that can add a company
// rule widens the boundary of unrelated tasks.
func TestTaskScopeCompanyExpandsOnlyTrustedRules(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	cs := d.Companies()
	companyID, _, err := cs.UpsertCompany("Scope Source Co", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.DeleteCompany(companyID) })

	if added, _, invalid, errs := cs.AddScope(companyID,
		[]string{"trusted.example"}, "operator", ScopeSourceManual); added != 1 || invalid != 0 || len(errs) != 0 {
		t.Fatalf("manual company scope: added=%d invalid=%d errs=%v", added, invalid, errs)
	}
	if added, _, invalid, errs := cs.AddScope(companyID,
		[]string{"agent-written.example"}, "agent tool", ScopeSourceAgent); added != 1 || invalid != 0 || len(errs) != 0 {
		t.Fatalf("agent company scope: added=%d invalid=%d errs=%v", added, invalid, errs)
	}

	task, err := d.CreateTaskWithOptions("scope company", "company link", TaskCreateOptions{
		CompanyIDs: []int64{companyID},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	blocked, err := d.CheckTaskScopeHosts(task.ID, []string{
		"app.trusted.example",   // manual company rule (domain covers subdomains)
		"agent-written.example", // agent-written rule: not authoritative
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 1 || blocked[0] != "agent-written.example" {
		t.Fatalf("blocked = %v, want [agent-written.example]", blocked)
	}
}
