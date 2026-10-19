# 三家 SRC 常见非洞速查（配合 src-triage）

判定时先在本表找类，再决定 drop / candidate。**表里没有 ≠ 就是洞**，仍要过六问。

## P5 / Informative / N/A（直接 drop）

| 类 | 例子 | 例外（才考虑留下） |
|---|---|---|
| 安全头 | 缺 CSP/HSTS/XFO/XCTO | 能配上具体点击劫持盗操作，且页面有状态改变 |
| Cookie 标志 | 缺 HttpOnly/Secure/SameSite | 该 Cookie 是会话 + 已有 XSS/CSRF 利用链 |
| TLS 硬化 | 套件、CAA、无 pinning | 可演示降级/拦截拿到会话 |
| 指纹 | Server 头、框架版本、phpinfo 无密钥 | 版本对应未修复 RCE 且你打出了 |
| 公开文件 | robots、sitemap、公开 swagger | swagger 暴露未文档化**管理**接口或密钥 |
| CSRF | 登出、GET、无登录 | 能改邮箱/支付/转账 |
| 点击劫持 | 营销页、文档 | 能在 iframe 里完成改密/授权 |
| CORS | `*` + 公开 GET | 带 cookie 且能读 PII |
| 重定向 | `?next=https://evil` | 偷 OAuth code/token |
| 枚举 | 登录显示「用户不存在」 | 能接到重置接管 |
| 策略 | 弱密码、无 MFA、无验证码 | 能实际接管（仍可能 OOS） |
| Self-XSS | 控制台粘贴 | 无 |
| JSON 假 XSS | API 回显 `<script>` | `browser_xss_evidence` dialog=true |
| SPA 200 | 任意路径 = 首页 sha256 | 正文真是 .git/HEAD、.env |
| 公开对象 | 公开 profile IDOR | 对象含非公开 PII |
| 前端假提权 | 改 JSON 显示 Admin | 管理 API 真 200 |
| 客户端 SSRF | curl -L 打到自己 | 后端 UA + 内网/metadata |
| 无影响逻辑 | 评分 -1、昵称特殊字符 | 钱/库存/角色/他人数据变化 |
| DoS | 慢速、大包 | 三家多数 OOS，不要测 |
| OOS | 第三方、营销站 | 无 |

## 必须对照，否则仍 drop

见主技能第 4 节：IDOR / 垂直越权 / XSS / SSRF / 泄露 / JWT / 接管 / 接管子域 / 价格券。

## Juice Shop 彩排对照（教学，禁止交三家）

| finding | 技术上 | 真实 SRC 会怎样 |
|---|---|---|
| JWT alg=none | 真洞 | 可报（靶场 never） |
| GET /api/Users 列全站 | 真 IDOR | 可报 |
| /ftp 目录 + poison null | 真泄露 | 可报；**不要报两次** |
| 搜索 DOM XSS dialog | 真 XSS | 可报 |
| 头像 URL SSRF 拉内网 | 真 SSRF | 可报；follow 302 的 OOB 不算 |
| rating=-1 入库 | 输入校验 | 多数 **N/A**（无钱无权） |
| CAPTCHA 回显 answer | 弱验证 | 多数 Informative，除非接到敏感操作 |
| 负数量下单改钱包 | 真逻辑 | 可报，金额以**当次**响应为准 |

靶场即使是真洞：`submit_advice=never`。
