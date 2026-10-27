package db

import (
	"fmt"
	"strings"
	"testing"
)

func TestRegressionDSLWrapped(t *testing.T) {
	node, err := ParseDSL("domain=a OR domain=b")
	if err != nil {
		t.Fatal(err)
	}
	where, _, err := buildDSLWhere(node)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("where=%s\n", where)
	if !strings.HasPrefix(where, "(") || !strings.HasSuffix(where, ")") {
		t.Fatalf("OR clause not wrapped: %s", where)
	}
}

func TestRegressionDSLOperators(t *testing.T) {
	for _, c := range []struct{ dsl, want string }{
		{"task_id=5", "= ANY"},
		{"task_id!=5", "NOT ("},
		{"company_id!=7", "<>"},
	} {
		node, err := ParseDSL(c.dsl)
		if err != nil {
			t.Fatalf("%s: %v", c.dsl, err)
		}
		where, _, err := buildDSLWhere(node)
		if err != nil || !strings.Contains(where, c.want) {
			t.Errorf("%s -> %q (%v), want %q", c.dsl, where, err, c.want)
		}
	}
	for _, bad := range []string{"task_id>5", "company_id>5"} {
		node, _ := ParseDSL(bad)
		if _, _, err := buildDSLWhere(node); err == nil {
			t.Errorf("%s should be rejected", bad)
		}
	}
}

func TestRegressionAssetGateMatching(t *testing.T) {
	block := []AssetInterceptRule{{Enabled: true, Kind: "exact_ip", Pattern: "::FFFF:203.0.113.5"}}
	if d := EvaluateAssetGate(block, nil, nil, []string{"203.0.113.5"}, nil); d.Allowed {
		t.Error("equivalent IP form must still be blocked")
	}
	allow := []AssetInterceptRule{{Enabled: true, Kind: "fuzzy_domain", Pattern: "example.com"}}
	for _, host := range []string{"example.com.evil.net", "notexample.com"} {
		if d := EvaluateAssetGate(nil, allow, []string{host}, nil, nil); d.Allowed {
			t.Errorf("allowlist escaped by %s", host)
		}
	}
	if d := EvaluateAssetGate(nil, allow, []string{"a.example.com"}, nil, nil); !d.Allowed {
		t.Error("subdomain of an allow rule must be allowed")
	}
	blk := []AssetInterceptRule{{Enabled: true, Kind: "fuzzy_ip", Pattern: "10."}}
	if d := EvaluateAssetGate(blk, nil, nil, []string{"110.1.2.3"}, nil); !d.Allowed {
		t.Error("110.1.2.3 must not match the 10. prefix")
	}
	if d := EvaluateAssetGate(blk, nil, nil, []string{"10.1.2.3"}, nil); d.Allowed {
		t.Error("10.1.2.3 must match the 10. prefix")
	}
}
