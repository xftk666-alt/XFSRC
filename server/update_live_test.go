package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Autumn-27/artex/selfupdate"
)

// 手工验证用：设置 ARTEX_UPDATE_TOKEN 后跑
//
//	ARTEX_PG_DSN=... ARTEX_UPDATE_TOKEN=xxx go test -run TestLiveUpdateCheck -v ./server
func TestLiveUpdateCheck(t *testing.T) {
	token := os.Getenv("ARTEX_UPDATE_TOKEN")
	if token == "" {
		t.Skip("set ARTEX_UPDATE_TOKEN")
	}
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	if err := m.pg.SetSetting(updateSettingsKey, `{"proxy":"http://172.18.0.1:3066","token":"`+token+`"}`); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m}
	client, network, err := s.updateClient()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("network=%q", network)
	rel, err := selfupdate.FetchLatest(context.Background(), client)
	if err != nil {
		t.Fatalf("FetchLatest: %v", err)
	}
	t.Logf("latest=%s assets=%d", rel.TagName, len(rel.Assets))

	for _, cur := range []string{"0.3.22-fix9", "0.3.22-fix10", "0.3.22"} {
		cmp, ok := selfupdate.CompareVersions(cur, rel.TagName)
		t.Logf("current=%s -> has_update=%v (cmp=%d comparable=%v)", cur, ok && cmp < 0, cmp, ok)
	}
	asset := selfupdate.AssetName(rel.TagName, "linux", "amd64")
	_, found := rel.FindAsset(asset)
	t.Logf("asset=%s found=%v", asset, found)
	if !found {
		t.Fatal("asset missing")
	}

	// 下载 + SHA256SUMS 校验 + 解包到临时目录，覆盖一键更新的高风险步骤。
	dir := t.TempDir()
	stageCtx := selfupdate.WithAPIAssets(context.Background())
	if err := selfupdate.StageTo(stageCtx, client, rel, "0.3.22-fix9", selfupdate.Paths{
		Current: filepath.Join(dir, "artex"),
		New:     filepath.Join(dir, "artex.new"),
		Sum:     filepath.Join(dir, "artex.new.sha256"),
		Old:     filepath.Join(dir, "artex.old"),
		Marker:  filepath.Join(dir, "artex.upgrade.json"),
	}, nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	st, err := os.Stat(filepath.Join(dir, "artex.new"))
	if err != nil {
		t.Fatalf("staged binary: %v", err)
	}
	t.Logf("staged artex.new = %d bytes", st.Size())
}
