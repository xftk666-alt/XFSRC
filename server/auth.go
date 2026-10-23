package server

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// authTokenVersionKey holds the JWT generation. Bumping it invalidates every
	// token issued before the bump — that is what makes "logout" and
	// "password changed" actually revoke a leaked 7-day token.
	authTokenVersionKey = "auth.token_version"
	// authSetupTokenKey holds the one-time token required by /api/auth/init for
	// non-loopback callers. Without it, anyone who reaches a fresh instance before
	// the operator finishes setup owns the platform.
	authSetupTokenKey = "auth.setup_token"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	// A key that exists but cannot be read or is too short is an error, not a
	// reason to mint a new one: regenerating silently revokes every outstanding
	// token, and two processes racing here would persist different keys.
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		key := strings.TrimSpace(string(data))
		if len(key) < 32 {
			return nil, fmt.Errorf("jwt key %s 过短（%d 字节），请检查文件完整性", path, len(key))
		}
		return []byte(key), nil
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("读取 jwt key %s 失败: %w", path, err)
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

// signJWT issues a 7-day HS256 token for the admin user (XFSRC). ver is the
// server's token generation: bumping it (password change, logout) invalidates
// every token issued before the bump, which is what makes revocation possible.
func signJWT(key []byte, ver int64) (string, error) {
	claims := jwt.MapClaims{
		"sub": "XFSRC",
		"exp": jwt.NewNumericDate(time.Now().Add(jwtTTL)),
		"iat": jwt.NewNumericDate(time.Now()),
		"ver": ver,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
}

// verifyJWT returns true when tokenStr is a valid, non-expired HS256 token whose
// generation matches ver. A token minted before a password change or logout no
// longer verifies, so a leaked token cannot outlive the operator's response.
func verifyJWT(tokenStr string, key []byte, ver int64) bool {
	if tokenStr == "" {
		return false
	}
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	if err != nil || !t.Valid {
		return false
	}
	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	got, ok := claims["ver"].(float64)
	return ok && int64(got) == ver
}

// isSSEPath reports whether a request is a Server-Sent Events stream. Browsers
// cannot set headers on EventSource, so these are the only endpoints where the
// token may travel in the query string — everywhere else it must come from the
// Authorization header or the HttpOnly cookie.
func isSSEPath(p string) bool {
	switch p {
	case "/api/logs/stream", "/api/update/stream", "/api/exploration/activity/stream":
		return true
	}
	return strings.HasSuffix(p, "/events")
}

const authCookieName = "artex_token"

// extractToken reads the JWT from the Authorization header, the HttpOnly
// artex_token cookie, or (SSE only) the ?token= query param.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie(authCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if isSSEPath(r.URL.Path) {
		return r.URL.Query().Get("token")
	}
	return ""
}

// setAuthCookie stores the JWT in an HttpOnly, SameSite=Strict cookie so page
// scripts (and therefore any XSS) cannot read it. Secure is set when the request
// arrived over TLS, including through a reverse proxy.
func setAuthCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(jwtTTL / time.Second),
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func clearAuthCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// requireAuth wraps h with JWT validation.
// /api/auth/*, /api/health and the Basic Auth gate check are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" || p == "/api/basic-auth/check" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, "未授权")
			return
		}
		if !s.tokenGenerationKnown() {
			writeErr(w, 503, "令牌代数不可用，请稍后重试")
			return
		}
		if !verifyJWT(tok, s.jwtKey, s.tokenVersion()) {
			writeErr(w, 401, "token 无效或已过期")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// 读失败必须回 503 而不是 initialized:false：前端在 initialized:false 时会把用户
// 送到 /setup 去设置密码（login/page.tsx），把数据库故障包装成 200 等于把用户往
// 覆盖已有密码的路上推。
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{
		"initialized": hash != "",
		// Only a request that already comes from the machine itself may claim a
		// fresh instance without proving it can read the server log.
		"requires_setup_token": hash == "" && !isLoopbackRequest(r),
	})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	// CSRF: this route is unauthenticated by necessity, so the browser's own
	// cross-origin markers are the only thing separating the operator from a page
	// the operator is visiting.
	if isBrowserCrossSite(r) {
		writeErr(w, 403, "拒绝跨站请求：请在服务器本机或直接访问本站完成初始化")
		return
	}
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "密码已设置")
		return
	}
	var req struct {
		Password   string `json:"password"`
		SetupToken string `json:"setup_token"`
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		writeErr(w, 400, "密码不能为空")
		return
	}
	// First-run takeover guard: a remote caller must present the token printed in
	// the server log. A local caller (the operator at the machine) is exempt so the
	// documented setup flow keeps working.
	if !isLoopbackRequest(r) {
		want, ok, serr := pg.GetSetting(authSetupTokenKey)
		if serr != nil {
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
		if !ok || want == "" || subtle.ConstantTimeCompare([]byte(req.SetupToken), []byte(want)) != 1 {
			writeErr(w, 403, "需要初始化令牌：请从服务端启动日志或 data/setup-token 获取 setup token")
			return
		}
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	// 用 INSERT ... ON CONFLICT DO NOTHING 而不是 upsert：上面那次 GetSetting 只是
	// 快速失败路径，真正"仅首次可设"的保证落在主键约束上。bcrypt 要跑几十毫秒，
	// 这期间别的请求完全可能先把密码设好，而读检查本身也可能因故障而失效。
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	if !inserted {
		writeErr(w, 403, "密码已设置")
		return
	}
	tok, err := signJWT(s.jwtKey, s.tokenVersion())
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	setAuthCookie(w, r, tok)
	// The setup token is single-use: a later reset of the password hash must not
	// let an old log line claim the instance again. The file goes too — a stale
	// credential file on disk is just noise an operator will try to use.
	_ = pg.SetSetting(authSetupTokenKey, "")
	if s.m != nil && s.m.dir != "" {
		_ = os.Remove(filepath.Join(s.m.dir, "setup-token"))
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !verifyJWT(extractToken(r), s.jwtKey, s.tokenVersion()) {
		writeErr(w, 401, "未授权")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "新密码不能为空")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 401, "当前密码错误")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	// Revoke first, persist second. If the bump fails we return 500 with the old
	// hash still in place, so the operator retries — whereas writing the new hash
	// first left a changed password alongside still-valid old tokens when the
	// bump failed (a leaked token kept working for its full 7-day life).
	ver, err := s.bumpTokenVersion()
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	if err := pg.SetSetting(authPassKey, string(newHash)); err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	// Hand the caller a fresh token so the operator is not logged out of their
	// own session.
	tok, err := signJWT(s.jwtKey, ver)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	setAuthCookie(w, r, tok)
	writeJSON(w, 200, map[string]any{"ok": true, "token": tok})
}

// POST /api/auth/logout — revokes every issued token by bumping the generation.
//
// This route lives under /api/auth/*, which requireAuth exempts, so it validates
// the token itself. Without that check any reachable client — including a
// cross-site form POST, which needs no preflight and cannot read the response —
// could bump the generation and log the administrator out of every device, over
// and over. The cookie is still cleared when the token is already invalid, so a
// stale browser session can always be cleaned up.
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !verifyJWT(extractToken(r), s.jwtKey, s.tokenVersion()) {
		clearAuthCookie(w, r)
		writeErr(w, 401, "未授权")
		return
	}
	if _, err := s.bumpTokenVersion(); err != nil {
		writeErr(w, 500, "登出失败: "+err.Error())
		return
	}
	clearAuthCookie(w, r)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// tokenVersion returns the current JWT generation (0 when the DB has none yet).
func (s *Server) tokenVersion() int64 { return s.tokenVer.Load() }

// tokenGenerationKnown reports whether the persisted generation was read
// successfully. While it is false every token is rejected: an unknown generation
// cannot be matched, and assuming 0 would un-revoke tokens.
func (s *Server) tokenGenerationKnown() bool { return !s.tokenVerUnknown.Load() }

// bumpTokenVersion persists and publishes the next generation.
func (s *Server) bumpTokenVersion() (int64, error) {
	if s.m.pg == nil {
		// Reporting success here made logout and password change silent no-ops
		// while every previously issued token kept verifying.
		return 0, errors.New("数据库不可用，无法递增令牌代数")
	}
	tx, err := s.m.pg.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	// Read-modify-write under the row lock so two concurrent bumps cannot both
	// land on the same value (which would resurrect a revoked token).
	//
	// The FOR UPDATE must sit on a query that actually has a FROM clause. The
	// previous form wrapped the read in a scalar subquery and put FOR UPDATE on
	// the outer SELECT, which has no FROM — PostgreSQL then locked nothing, so
	// concurrent bumps both read N and both wrote N+1 (verified: no blocking, and
	// the value advanced once instead of twice). Seed the row first so the lock
	// always has a tuple to take, then lock and bump it.
	var cur int64
	if _, err = tx.Exec(`INSERT INTO settings(key, value) VALUES ($1, '0')
ON CONFLICT (key) DO NOTHING`, authTokenVersionKey); err != nil {
		return 0, err
	}
	if err = tx.QueryRow(`SELECT value::bigint FROM settings WHERE key=$1 FOR UPDATE`,
		authTokenVersionKey).Scan(&cur); err != nil {
		return 0, err
	}
	next := cur + 1
	if _, err := tx.Exec(`UPDATE settings SET value=$2, updated_at=now() WHERE key=$1`,
		authTokenVersionKey, strconv.FormatInt(next, 10)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.tokenVer.Store(next)
	return next, nil
}

// loadTokenVersion primes the in-memory generation from the DB at startup.
func (s *Server) loadTokenVersion() {
	if s.m.pg == nil {
		return
	}
	raw, ok, err := s.m.pg.GetSetting(authTokenVersionKey)
	if err != nil {
		// A transient read failure must not be mistaken for "generation 0":
		// that value is what every token issued before the first logout or
		// password change carries, so a restart during a DB blip would make
		// revoked tokens valid again. Refuse to verify until a later reload
		// succeeds.
		log.Printf("[auth] 读取令牌代数失败，已暂停令牌校验（fail-closed）: %v", err)
		s.tokenVerUnknown.Store(true)
		return
	}
	if !ok {
		// No row yet: this instance has never bumped, so generation 0 is the
		// real value, not a guess.
		s.tokenVer.Store(0)
		s.tokenVerUnknown.Store(false)
		return
	}
	v, perr := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if perr != nil {
		log.Printf("[auth] 令牌代数无法解析（%q），已暂停令牌校验（fail-closed）: %v", raw, perr)
		s.tokenVerUnknown.Store(true)
		return
	}
	s.tokenVer.Store(v)
	s.tokenVerUnknown.Store(false)
}

// ensureSetupToken generates (and persists + logs) the first-run setup token when
// no admin password exists yet. It is written to dataDir/setup-token so an
// operator with shell access can read it without digging through logs, and the
// file is removed as soon as the password is set.
func (s *Server) ensureSetupToken(dataDir string) {
	if s.m.pg == nil {
		return
	}
	hash, _, err := s.m.pg.GetSetting(authPassKey)
	if err != nil {
		// A transient read error must not regenerate the token: that would
		// invalidate one already handed to the operator.
		log.Printf("[auth] 读取密码状态失败，跳过 setup token 生成: %v", err)
		return
	}
	if hash != "" {
		_ = os.Remove(filepath.Join(dataDir, "setup-token"))
		return
	}
	tok, ok, err := s.m.pg.GetSetting(authSetupTokenKey)
	if err != nil {
		log.Printf("[auth] 读取 setup token 失败，保留现有令牌: %v", err)
		return
	}
	if !ok || strings.TrimSpace(tok) == "" {
		buf := make([]byte, 24)
		for i := range buf {
			n, rerr := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
			if rerr != nil {
				log.Printf("[auth] 生成 setup token 失败: %v", rerr)
				return
			}
			buf[i] = keyChars[n.Int64()]
		}
		tok = string(buf)
		if err := s.m.pg.SetSetting(authSetupTokenKey, tok); err != nil {
			log.Printf("[auth] 保存 setup token 失败: %v", err)
			return
		}
	}
	path := filepath.Join(dataDir, "setup-token")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.Printf("[auth] 写入 setup token 文件失败: %v", err)
	} else if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		log.Printf("[auth] 写入 setup token 文件失败: %v", err)
	}
	log.Printf("[auth] 首次初始化令牌 (setup token): %s  — 远程访问 /setup 时必须填写；本机访问可留空。文件: %s", tok, path)
}

// isLoopbackRequest reports whether the request originates on this machine.
//
// A loopback RemoteAddr alone is not enough: behind the documented nginx setup
// EVERY request arrives from 127.0.0.1, so treating that as "local" would hand
// the setup-token exemption to any remote caller. When a forwarded client address
// is present it decides; only a request with no forwarded address and a loopback
// peer is treated as local.
func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	if fwd := forwardedClientIP(r); fwd != "" {
		fip := net.ParseIP(fwd)
		return fip != nil && fip.IsLoopback()
	}
	// A browser is never "the operator at the machine", whatever address the
	// request appears to come from. Without this, the documented nginx block
	// (which sets no X-Forwarded-For) makes every remote caller look local, and a
	// cross-site form POST to /api/auth/init could claim a fresh instance.
	return !isBrowserCrossSite(r)
}

// isBrowserCrossSite reports whether a browser made this request from another
// origin. Browsers always attach Origin to a cross-origin POST and Sec-Fetch-Site
// to every request; a command-line client attaches neither.
func isBrowserCrossSite(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "cross-site", "same-site":
		return true
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return true
	}
	return !strings.EqualFold(u.Host, r.Host)
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	client := loginClientKey(r)
	if s.loginLimit != nil {
		if ok, wait := s.loginLimit.allow(client); !ok {
			s.loginLimit.reject(w, wait)
			return
		}
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.Username != "XFSRC" {
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	if s.loginLimit != nil {
		s.loginLimit.reset(client)
	}
	tok, err := signJWT(s.jwtKey, s.tokenVersion())
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	setAuthCookie(w, r, tok)
	writeJSON(w, 200, map[string]any{"token": tok})
}
