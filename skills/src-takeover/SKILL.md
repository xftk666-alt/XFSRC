---
name: src-takeover
description: 海外 SRC 授权范围内的子域接管（CNAME/NS 指向已释放的 GitHub Pages、S3、Azure、Heroku 等）验证流程。当 subfinder/dnsx/gf takeovers 发现悬空 DNS 或需要按三平台要求证明可接管时使用。只做认领证明，不挂钓鱼页。
---
# 海外 SRC：子域接管（Subdomain Takeover）

已授权 program 的 **in-scope 子域**。目标：证明 DNS 仍指向你可认领的第三方，并给出 **PoC 页面或平台认领截图**——不要真的去做钓鱼。

配套：`overseas-src-recon` 子域阶段 → 本技能 → **`src-triage`（只有 404 文案、无法认领 = 不是洞）** → `src-retest` → `src-report-writing`。

---

## 0. 合规

- [ ] 子域本身 in-scope（`*.example.com` 通常包含；**明确 OOS 的营销子域不要碰**）
- [ ] 只证明可接管；**不要**部署钓鱼、不要收凭据
- [ ] 部分 program 要求接管后放指定 token 文件
- [ ] 不要对无关云账户做破坏性删除

---

## 1. 发现悬空记录

```
subfinder_enum / crtsh_enum → dnsx_resolve
```

关注：CNAME 到 `github.io` `herokuapp.com` `cloudfront.net` `s3.amazonaws.com` `azurewebsites.net` `trafficmanager.net` `readme.io` `zendesk.com` `shopify` `netlify.app` `vercel.app` 等。

历史 URL 侧：

```
gau_urls → 写入文件 → gf_filter(file=..., pattern="takeovers")
```

httpx 对子域探活：若 **DNS 有记录但 HTTP 是第三方默认 404**（GitHub Pages 的 `There isn't a GitHub Pages site here`、Heroku `No such app`、S3 `NoSuchBucket`）→ 候选。

`cdncheck_detect`：在 CDN 后的主站不是接管；接管看的是 **这颗子域自己的 CNAME**。

---

## 2. 验证（必须能认领，不能只看报错页）

1. 解析：`dnsx_resolve` 拿到 CNAME 链
2. 打开该 CNAME 目标，确认是「资源不存在」而不是「存在但别人的」
3. 用你控制的对应平台账号 **认领同名资源**（GitHub repo 开 Pages、S3 开同名桶、Azure 开同名 app）
4. 在子域上看到 **你放的内容**（一行 `SRC-TAKEOVER-POC by <your handle>`）才算
5. 截图 DNS + 页面；报告后按 program 要求删除 PoC 页

**误报**：CNAME 到仍存在的客户资源、NXDOMAIN 但无权在该云创建同名、需要原账号验证的 Fastly/Cloudflare 等（很多「已知不可接管」）。验证不了就不要报。

---

## 3. 定级

| 证据 | 建议 |
|---|---|
| 能在 in-scope cookie 域下执行任意内容（会话域接管） | High～Critical |
| 独立子域、无共享 cookie，仅内容 | Medium |
| 只有 404 文案、无法认领 | 不报 |

---

## 4. 工具

`subfinder_enum` `crtsh_enum` `dnsx_resolve` `httpx_probe` `gf_filter` `browser` MCP  
先 `src-triage`；candidate 才 `report_finding`（vulnclass=`subdomain-takeover`）→ `src-retest`
