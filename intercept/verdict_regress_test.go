package intercept

import (
	"strings"
	"testing"
)

func TestRegressionVerdictSafety(t *testing.T) {
	long := strings.Repeat("实际操作：删库；成功后的后果：数据全丢；", 200)
	denyish := []string{
		`{"decision":"deny","comment":"实际操作：执行 rm；成功后的后果：删除文件","confidence":0.95}`,
		`{"decision":"deny","comment":"实际操作：执行 rm；成功后的后果：删除文件","extra":true}`,
		`{"decision":"deny","comment":"` + long + `"}`,
		`{"decision":"ask","comment":"实际操作：执行 rm；成功后的后果：删除文件","confidence":1}`,
	}
	for _, in := range denyish {
		if got := ParseVerdict(in); got.Action == "" {
			t.Errorf("safe-direction verdict was discarded: %.80s", in)
		}
	}
	permissive := []string{
		`{"decision":"allow","comment":"实际操作：读取；成功后的后果：返回内容；命中规则：A5","extra":true}`,
		`{"decision":"allow","comment":"` + long + `"}`,
	}
	for _, in := range permissive {
		if got := ParseVerdict(in); got.Action != "" {
			t.Errorf("permissive verdict accepted on a malformed reply: %.80s", in)
		}
	}
}
