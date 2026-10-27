package agent

import "testing"

// TestRegressionGoalsScopeMustBeOperatorStated pins the rule that keeps a
// decomposer-derived hostname out of the trusted scope: only text the operator
// actually wrote may authorize a target.
func TestRegressionGoalsScopeMustBeOperatorStated(t *testing.T) {
	cases := []struct {
		text, value string
		want        bool
	}{
		{"授权范围只有 allowed.example", "allowed.example", true},
		{"目标站点 https://allowed.example/", "allowed.example", true},
		{"授权范围只有 allowed.example", "foo.localhost", false},
		{"客户给的资产清单批量存活探测", "bar.localhost", false},
		{"", "allowed.example", false},
	}
	for _, c := range cases {
		ts := &ToolSet{worker: "goals", operatorText: c.text}
		if got := ts.scopeStatedByOperator(c.value); got != c.want {
			t.Errorf("text=%q value=%q: got %v want %v", c.text, c.value, got, c.want)
		}
	}
}
