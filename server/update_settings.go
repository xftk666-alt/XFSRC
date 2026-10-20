package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/selfupdate"
)

const updateSettingsKey = "update.network"

type updateSettings struct {
	Proxy string `json:"proxy"`
	// Token 是读取私有仓库 Release 用的 GitHub Token（只读权限即可）。
	// 仓库为 private 时，未认证的 /releases/latest 会返回 404。
	Token string `json:"token"`
}

func (cfg *updateSettings) validate() error {
	cfg.Proxy = strings.TrimSpace(cfg.Proxy)
	if _, err := selfupdate.ParseProxy(cfg.Proxy); err != nil {
		return err
	}
	return nil
}

func (s *Server) loadUpdateSettings() (updateSettings, error) {
	cfg := updateSettings{}
	raw, ok, err := s.m.pg.GetSetting(updateSettingsKey)
	if err != nil {
		return cfg, fmt.Errorf("读取更新网络设置失败: %w", err)
	}
	if ok {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return cfg, fmt.Errorf("更新网络设置格式无效")
		}
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (s *Server) getUpdateSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadUpdateSettings()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"proxy":     cfg.Proxy,
		"token_set": cfg.Token != "",
	})
}

func (s *Server) putUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proxy string  `json:"proxy"`
		Token *string `json:"token"` // nil = 不修改，"" = 清空
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeErr(w, 400, "更新网络设置格式无效")
		return
	}
	cur, err := s.loadUpdateSettings()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	cfg := updateSettings{Proxy: req.Proxy, Token: cur.Token}
	if req.Token != nil {
		cfg.Token = strings.TrimSpace(*req.Token)
	}
	if err := cfg.validate(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := s.m.pg.SetSettingContext(r.Context(), updateSettingsKey, string(raw)); err != nil {
		writeErr(w, 500, "保存更新网络设置失败")
		return
	}
	writeJSON(w, 200, map[string]any{
		"proxy":     cfg.Proxy,
		"token_set": cfg.Token != "",
	})
}

// Capture one effective proxy for both release discovery and all asset downloads.
// A different proxy bypasses cached success/error results from the previous route.
func (s *Server) updateClient() (*http.Client, string, error) {
	cfg, err := s.loadUpdateSettings()
	if err != nil {
		return nil, "", err
	}
	client, err := selfupdate.NewClient(cfg.Proxy)
	if err != nil {
		return nil, "", err
	}
	if token := strings.TrimSpace(cfg.Token); token != "" {
		client.Transport = &authTransport{base: client.Transport, token: token}
	}
	return client, cfg.Proxy, nil
}

// updateUsesToken reports whether a GitHub token is configured (private repo).
func (s *Server) updateUsesToken() bool {
	cfg, err := s.loadUpdateSettings()
	return err == nil && strings.TrimSpace(cfg.Token) != ""
}

// authTransport adds the GitHub Authorization header to every update request.
// The repository is private, so the unauthenticated releases API returns 404.
type authTransport struct {
	base  http.RoundTripper
	token string
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(clone)
}
