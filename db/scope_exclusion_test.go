package db

import (
	"testing"
)

// Exclusions must beat inclusions. The platforms all publish both lists, and a
// gate that ORs them together would authorise exactly the hosts the program
// marked off-limits.
func TestExclusionBeatsInclusion(t *testing.T) {
	d, _, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("excl", "excl", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	id := task.ID

	_, _, err = d.Assets().ReplacePlatformScope(id, []PlatformScopeRule{
		{Kind: "root_domain", Value: "example.com"},
		{Kind: "subdomain", Value: "admin.example.com", Excluded: true},
		{Kind: "cidr", Value: "10.0.0.0/24"},
		{Kind: "ip", Value: "10.0.0.9", Excluded: true},
		{Kind: "ip", Value: "203.0.113.5"},
	}, "hackerone@test")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		host    string
		blocked bool
	}{
		{"api.example.com", false},   // covered by the root domain
		{"admin.example.com", true},  // explicit exclusion
		{"10.0.0.7", false},          // inside the CIDR
		{"10.0.0.9", true},           // explicit exclusion inside the CIDR
		{"203.0.113.5", false},       // exact IP
		{"203.0.113.6", true},        // outside every rule
	}
	for _, tc := range cases {
		blocked, err := d.CheckTaskScopeHosts(id, []string{tc.host}, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.host, err)
		}
		gotBlocked := len(blocked) > 0
		if gotBlocked != tc.blocked {
			t.Errorf("%s: blocked=%v, want %v", tc.host, gotBlocked, tc.blocked)
		}
	}
}

// An import replaces the platform list but must not touch what the operator
// typed by hand or what the goal decomposer wrote.
func TestImportReplacesOnlyPlatformRows(t *testing.T) {
	d, assets, _ := testSetup(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("keep", "keep", TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	id := task.ID

	if _, err := assets.AddAgentScope(id, "root_domain", "manual.example", "operator", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := assets.ReplacePlatformScope(id, []PlatformScopeRule{
		{Kind: "root_domain", Value: "first.example"},
	}, "hackerone@v1"); err != nil {
		t.Fatal(err)
	}
	added, removed, err := assets.ReplacePlatformScope(id, []PlatformScopeRule{
		{Kind: "root_domain", Value: "second.example"},
	}, "hackerone@v2")
	if err != nil {
		t.Fatal(err)
	}
	if added != 1 || removed != 1 {
		t.Fatalf("re-import: added=%d removed=%d, want 1/1", added, removed)
	}

	rows, err := assets.ListTaskScope(id)
	if err != nil {
		t.Fatal(err)
	}
	var manual, first, second bool
	for _, r := range rows {
		switch {
		case r.Source == "manual" && r.Domain == "manual.example":
			manual = true
		case r.Source == "platform" && r.Domain == "first.example":
			first = true
		case r.Source == "platform" && r.Domain == "second.example":
			second = true
		}
	}
	if !manual {
		t.Error("manual scope was deleted by the import")
	}
	if first {
		t.Error("stale platform row survived the re-import")
	}
	if !second {
		t.Error("new platform row missing")
	}
}
