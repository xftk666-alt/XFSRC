---
name: src-file-upload
description: 海外 SRC 授权范围内的文件上传漏洞测试。覆盖扩展名/Content-Type/魔术字节绕过、polyglot、.htaccess、SVG/XXE、压缩包解压、文件名路径穿越、竞态。确认标准是文件被服务端解析执行或写到预期外位置，而不是"上传成功"。用于头像、附件、导入、文档预览等功能。
---
# src-file-upload — 文件上传漏洞

> 判据参考开源项目 Xalgorix（Apache-2.0，作者 Krishna Kumar / xalgord）的 web-application-security 技能库，已按本平台的授权范围与反误报要求重写，未照搬其工具链。


面向**已授权** program。目标：证明上传的文件**被服务端解析/执行**，或**写到了预期外的位置**。仅"上传成功返回 200"不算洞。

配套：`src-scope-guard` → 本技能 → `src-triage` → `src-retest` → `src-report-writing`。

---

## 0. 合规红线

- [ ] 目标 in-scope
- [ ] payload 只用**无害标记**（`<?php echo "MARKER123"; ?>`、`<svg onload=alert(document.domain)>`），不写 webshell、不持久化、不反弹
- [ ] 测试后尽量删除上传物；不能删则在报告中说明
- [ ] 禁止上传到会公开分发的目录造成传播
- [ ] 禁止 DoS 型大文件/压缩炸弹

---

## 1. 先判断上传后的处理链

| 处理方式 | 观察点 |
|---|---|
| 直存静态目录 | 返回的 URL 能否直接访问、Content-Type 是什么 |
| 对象存储/CDN | 独立域名、签名 URL、是否可执行 |
| 图片处理 | 是否重新编码（重编码可消除 polyglot） |
| 文档预览 | 是否服务端解析（PDF/Office/SVG） |
| 解压导入 | 是否解 zip/tar（zip slip） |

---

## 2. 绕过清单（不试完不许说 clean）

### 2.1 扩展名
```
shell.php
shell.php5 / .phtml / .pht / .phar
shell.php.jpg
shell.jpg.php
shell.php.  (尾点)
shell.php%20 (尾空格)
shell.php%00.jpg (NUL)
shell.PHP / .PhP (大小写)
shell.php;.jpg
shell.php/.jpg
```

### 2.2 Content-Type
`image/jpeg`、`image/png`、`text/plain`、`application/octet-stream` 互换。

### 2.3 魔术字节 / polyglot
- GIF89a + PHP
- JPEG 头 + HTML/JS
- SVG（可含 JS / XXE）
- PDF（可含 JS / 外部实体）

### 2.4 配置/解析
- `.htaccess` / `web.config` 上传（若允许）
- 双扩展名与服务器解析顺序
- 文件名路径穿越：`../../tmp/x`、`..%2f..%2f`、绝对路径

### 2.5 压缩包
- zip slip：条目名 `../../evil`
- 解压后文件类型是否二次校验
- 压缩炸弹（**不做**，只记录未测）

### 2.6 竞态
- 上传后短暂可访问、校验异步删除 → 需精确时间窗，谨慎

---

## 3. 确认判据

**必须至少满足一条**：

1. **执行**：访问上传 URL，服务端执行了你的标记（响应含 `MARKER123`，而不是源码文本）
2. **解析**：SVG/HTML 在你的 payload 下触发 JS（浏览器实测 `dialog_executed=true`）
3. **路径穿越**：文件出现在预期目录之外（如覆盖配置/模板），且有可验证证据
4. **XXE**：解析器请求了你的 OOB 域名（判据见 `src-ssrf`）
5. **覆盖**：能覆盖他人/系统文件（需极谨慎，仅证明到可控范围）

**不算证据**：
- 上传返回 200
- 文件可下载但 Content-Type 是 `application/octet-stream` 且不执行
- 图片被重编码（polyglot 失效）
- 只在 CDN 上静态托管，无服务端解析

---

## 4. 误报排除

| 现象 | 为什么不是洞 |
|---|---|
| 上传成功但访问 404 | 未落盘或异步清理 |
| 访问返回源码文本 | 未执行 |
| 图片被重新编码 | 净化有效 |
| SVG 被强制 `Content-Disposition: attachment` | 不执行 |
| 只在你自己浏览器显示 | 需服务端解析证据 |
| 上传到独立对象存储域 | 通常不执行（除非可改 Content-Type） |

---

## 5. 定级

| 证据 | 建议 |
|---|---|
| 服务端执行任意代码（无害标记） | Critical |
| 存储型 XSS（SVG/HTML 在他人浏览器执行） | High |
| 路径穿越写文件 | High~Critical |
| XXE 读到文件 | High |
| 仅可上传不允许的类型但不执行 | Low / informational |
| 仅缺少 `Content-Disposition` | Low |

---

## 6. 工具对照

| 目的 | 工具 |
|---|---|
| 上传与访问 | curl（`-F`） |
| 浏览器执行验证 | browser 工具 / `browser_xss_evidence` |
| OOB（XXE） | `oob_gen` / `oob_poll` |
| 证据 | `http_evidence_record`（上传请求 + 访问响应）+ 截图 |
| 台账 | `coverage_record`（risk=`insecure_file_upload`） |
| 复测 | `src-retest` |

---

## 7. 报告要点

- 上传点与允许的类型
- 绕过串（扩展名/类型/魔术字节）
- 访问 URL 与服务端行为（执行/解析/穿越）
- 影响：能否执行代码、影响哪些用户
- 修复：白名单扩展名 + 服务端内容校验 + 重编码 + 存储与执行分离 + 随机文件名 + 禁止路径穿越
