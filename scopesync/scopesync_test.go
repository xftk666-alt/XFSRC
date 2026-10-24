package scopesync

import (
	"testing"
)

// The parser decides what the authorization gate will enforce, so these tests
// check the two ways it can be wrong in a legally meaningful direction: dropping
// an authorised target, and widening an exact host into its whole tree.

func TestParseHackerOne(t *testing.T) {
	payload := []byte(`{"data":[
      {"attributes":{"asset_identifier":"*.example.com","asset_type":"WILDCARD","eligible_for_submission":true,"instruction":"主域及其子域"}},
      {"attributes":{"asset_identifier":"api.example.com","asset_type":"URL","eligible_for_submission":true}},
      {"attributes":{"asset_identifier":"admin.example.com","asset_type":"URL","eligible_for_submission":false,"instruction":"明确排除"}},
      {"attributes":{"asset_identifier":"203.0.113.7","asset_type":"IP_ADDRESS","eligible_for_submission":true}},
      {"attributes":{"asset_identifier":"198.51.100.0/24","asset_type":"CIDR","eligible_for_submission":true}}
    ]}`)
	rules, err := Parse(HackerOne, payload)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Rule{
		"root_domain:example.com":  {Kind: "root_domain", Value: "example.com"},
		"subdomain:api.example.com": {Kind: "subdomain", Value: "api.example.com"},
		"subdomain:admin.example.com": {Kind: "subdomain", Value: "admin.example.com", Excluded: true},
		"ip:203.0.113.7":            {Kind: "ip", Value: "203.0.113.7"},
		"cidr:198.51.100.0/24":      {Kind: "cidr", Value: "198.51.100.0/24"},
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d: %+v", len(rules), len(want), rules)
	}
	for _, r := range rules {
		k := r.Kind + ":" + r.Value
		w, ok := want[k]
		if !ok {
			t.Errorf("unexpected rule %s (excluded=%v)", k, r.Excluded)
			continue
		}
		if r.Excluded != w.Excluded {
			t.Errorf("%s: excluded = %v, want %v", k, r.Excluded, w.Excluded)
		}
		if k == "subdomain:admin.example.com" && r.Note != "明确排除" {
			t.Errorf("instruction not carried into the note: %q", r.Note)
		}
	}
}

// A wildcard authorises the tree; a bare exact host must NOT be widened to it.
func TestBareHostIsNotWidened(t *testing.T) {
	payload := []byte(`{"data":[
      {"attributes":{"asset_identifier":"api.example.com","asset_type":"URL","eligible_for_submission":true}},
      {"attributes":{"asset_identifier":"example.org","asset_type":"DOMAIN","eligible_for_submission":true}}
    ]}`)
	rules, err := Parse(HackerOne, payload)
	if err != nil {
		t.Fatal(err)
	}
	byValue := map[string]string{}
	for _, r := range rules {
		byValue[r.Value] = r.Kind
	}
	if byValue["api.example.com"] != "subdomain" {
		t.Errorf("exact host became %q; widening it authorises hosts the program never offered", byValue["api.example.com"])
	}
	if byValue["example.org"] != "root_domain" {
		t.Errorf("DOMAIN asset type should cover the tree, got %q", byValue["example.org"])
	}
}

func TestParseBugcrowd(t *testing.T) {
	payload := []byte(`{"scope":[
      {"target":"*.shop.example","category":"website","in_scope":true},
      {"target":"legacy.example","category":"website","in_scope":false,"description":"已下线"}
    ]}`)
	rules, err := Parse(Bugcrowd, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules: %+v", len(rules), rules)
	}
	if rules[0].Kind != "root_domain" || rules[0].Excluded {
		t.Errorf("wildcard should be an included root_domain: %+v", rules[0])
	}
	if !rules[1].Excluded {
		t.Errorf("out-of-scope entry not marked excluded: %+v", rules[1])
	}
}

func TestParseIntigriti(t *testing.T) {
	payload := []byte(`{"scope":[
      {"endpoint":"https://app.example.io/login","type":"URL","inScope":true},
      {"endpoint":"10.0.0.0/8","type":"CIDR","inScope":true}
    ]}`)
	rules, err := Parse(Intigriti, payload)
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].Kind != "subdomain" || rules[0].Value != "app.example.io" {
		t.Errorf("URL endpoint should reduce to its host: %+v", rules[0])
	}
	if rules[1].Kind != "cidr" {
		t.Errorf("CIDR endpoint misclassified: %+v", rules[1])
	}
}

// Bad input must fail loudly. An empty rule set is indistinguishable from "this
// engagement authorises nothing", so silently returning it would hide the error
// until the agent could not reach anything.
func TestParseRejectsUnusableInput(t *testing.T) {
	cases := []struct {
		name     string
		platform string
		payload  string
	}{
		{"unknown platform", "hacktivity", `{}`},
		{"empty scope", HackerOne, `{"data":[]}`},
		{"not json", HackerOne, `not json`},
		{"missing target", Bugcrowd, `{"scope":[{"category":"website"}]}`},
		{"garbage host", HackerOne, `{"data":[{"attributes":{"asset_identifier":"not a host","asset_type":"URL","eligible_for_submission":true}}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.platform, []byte(tc.payload)); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}

func TestDedupeKeepsExclusion(t *testing.T) {
	rules := dedupe([]Rule{
		{Kind: "subdomain", Value: "a.example"},
		{Kind: "subdomain", Value: "a.example", Excluded: true},
	})
	if len(rules) != 2 {
		t.Fatalf("an exclusion must not collapse into the inclusion: %+v", rules)
	}
}
