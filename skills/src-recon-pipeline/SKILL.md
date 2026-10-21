---
name: src-recon-pipeline
description: 授权范围侦察流水线编排：泛解析前置硬门 → 子域召回 → 探活指纹 → 爬取/JS 静态分析 → 目录与 API 发现 → 参数发现 → 接管检查，带 partial recon（单阶段失败可重跑、结果合并回资产库）与限速档位。用于拿到一个已授权 program 的 in-scope 资产后，按标准顺序跑完侦察并登记资产。
---
# src-recon-pipeline — 授权范围内的侦察编排

## 前置硬门（不可跳过）

1. `src-roe-parser` 已完成：policy 已解析、`task_scope` 已写、`set_constraints` 已写。
2. `scope_check` 对每个根域名返回 in-scope。
3. 任一条不满足 → **不发任何请求**。

## 阶段与工具

| 阶段 | 工具 | 输出 | 失败处理 |
|---|---|---|---|
| 0. 泛解析门 | `puredns_check(domain)` | `WILDCARD_DETECTED` / `WILDCARD_NONE` | 检出泛解析 → 后续子域必须过滤；若解析到 CDN，标 out-of-scope 候选 |
| 1. 子域召回 | `subfinder`、`crtsh`、`gau`（仅公开历史） | 子域清单 | 单源失败不影响其它源 |
| 2. 解析与过滤 | `puredns_check(domain, candidates_file)` | 真实解析的子域 | 无解析的丢弃 |
| 3. 探活与指纹 | `httpx_probe(targets)` / `recon_fanout(url, light)` | 状态码/标题/技术栈 | 单个 host 失败跳过 |
| 4. 爬取 | `recon_fanout(url, light)` → `katana` | URL 清单 | 重 JS 站点补 `browser` |
| 5. JS 静态分析 | `jsluice_scan(js_url)` | endpoints / 疑似密钥 | 逐个 JS 跑；密钥只记录不验证 |
| 6. 目录发现 | `ffuf_fuzz(url/FUZZ, wordlist)` | 路径 | 低速率；只跑 common/api/graphql/backup 四本 |
| 7. 参数发现 | `arjun_discover(url)` | 隐藏参数 | 只对已确认 in-scope 且返回 2xx 的 URL |
| 8. 接管检查 | `subjack_check(hosts_file)` | 接管候选 | 命中必须人工证明可控 |
| 9. GraphQL | `graphql_cop(url)` | 误配项 | 只在发现 /graphql 时跑 |
| 10. 登记 | `insert_assets` | 资产库 | 分类型批量写 |

## partial recon（重要）

任何阶段失败**不要重跑整条**：

1. 每个阶段把输出写到 `$WORK/<stage>.txt`。
2. 重跑只跑该阶段，读上游已有文件作为输入。
3. 结果 `insert_assets` 时用**幂等**语义（同 host 同 type 不重复）。
4. 记录「哪些阶段完成、哪些失败」到 fact，供 `src-coverage` 引用。

## 限速档位（必须显式声明）

| 档位 | 场景 | 参数 |
|---|---|---|
| `stealth` | policy 禁止自动化或限速 < 5 rps | 只手工 + httpx 单线程；不跑 ffuf/nuclei |
| `normal` | 默认 | httpx 默认；katana `-rl 50 -c 10`；ffuf `-t 20 -rate 50`；arjun `-t 5 --rate-limit 20` |
| `fast` | 明确允许且目标健壮 | katana `-rl 150`；ffuf `-t 40 -rate 150` |

**policy 优先于档位。** 冲突时取更保守的。

## 输出清单（交给下一步）

```markdown
## Recon Summary
- domain / program / policy: ...
- wildcard: detected|none  (evidence: puredns output)
- subdomains: N (sources: ...)
- live hosts: N  (httpx)
- urls: N  (katana)
- js endpoints: N  (jsluice)
- dirs: N  (ffuf)
- params: N  (arjun)
- takeover candidates: N  (subjack)
- graphql endpoints: N  (graphql_cop)
- failures: [stage: reason]
- assets inserted: N
```

这份摘要直接喂给 `src-taxonomy`（选测哪些类）和 `src-coverage`（记覆盖）。

## 铁律

1. **泛解析门不过，不进入子域阶段**。否则后面所有工作都在假资产上。
2. **每个请求前 scope_check**。批量目标要逐个检查，不能只看根域。
3. **不跑全量 nuclei**。只对暴露面跑 `tags=exposure,config` 并手工验证。
4. **不做 subfinder 之外的主动爆破**（除非 policy 明确允许）。
5. **密钥只记录不验证**（`trufflehog_scan` 默认 `--no-verification`）。
6. **接管命中只是候选**，必须证明能实际控制才报。

## 确认判据与误报排除

- 只把「能被别人独立复现的成功证据」当证据；单一 200/单次命中不算。
- 先跑对照（匿名/低权/另一账号），能解释成自身数据或公开内容的，一律按误报排除。
- 结论写清「确认判据」：请求、响应字段、对照结果三者同时成立才算成立。

