#!/usr/bin/env node
/**
 * 独立浏览器 XSS 证据：打开 URL、捕获 dialog、截图、读 sink innerHTML。
 * 不信任模型口述「弹了 alert」。
 *
 * node browser_xss_evidence.js --url URL --outdir DIR --name NAME [--selector CSS] [--wait-ms 4000]
 */
const fs = require("fs");
const path = require("path");
const { chromium } = require("/usr/lib/node_modules/playwright");

function arg(name, def) {
  const i = process.argv.indexOf("--" + name);
  if (i < 0) return def;
  const v = process.argv[i + 1];
  if (!v || /^\{[a-zA-Z0-9_]+\}$/.test(v)) return def;
  return v;
}

function hostOf(u) {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function isPriv(h) {
  if (!h) return false;
  if (["juice-shop", "localhost", "host.docker.internal"].includes(h)) return true;
  if (h.endsWith(".local") || h.endsWith(".juice-sh.op") || h === "juice-sh.op") return true;
  if (/^(10\.|192\.168\.|127\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(h)) return true;
  return false;
}

(async () => {
  const url = arg("url", "");
  const outdir = arg("outdir", "");
  const name = (arg("name", "xss") || "xss").replace(/[^a-zA-Z0-9._-]+/g, "_");
  const selector = arg("selector", "#searchValue");
  const waitMs = parseInt(arg("wait-ms", "4000"), 10) || 4000;
  if (!url || !outdir) {
    console.error("ERROR: --url and --outdir required");
    process.exit(2);
  }
  const caseDir = path.join(path.resolve(outdir), "cases", name);
  fs.mkdirSync(caseDir, { recursive: true });

  const dialogs = [];
  const chrome =
    process.env.PLAYWRIGHT_CHROME ||
    "/root/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome";

  const priv = isPriv(hostOf(url));
  if (priv) {
    for (const k of [
      "HTTP_PROXY",
      "HTTPS_PROXY",
      "http_proxy",
      "https_proxy",
      "ALL_PROXY",
      "all_proxy",
    ]) {
      delete process.env[k];
    }
    process.env.NO_PROXY = "*";
    process.env.no_proxy = "*";
  }

  const launchOpts = {
    executablePath: chrome,
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
    env: { ...process.env },
  };
  if (priv) {
    launchOpts.proxy = { server: "direct://" };
    launchOpts.args.push("--proxy-bypass-list=<-loopback>;juice-shop;172.18.0.0/16;10.0.0.0/8;192.168.0.0/16;127.0.0.1;localhost");
  }

  const browser = await chromium.launch(launchOpts);
  const ctx = await browser.newContext({
    ignoreHTTPSErrors: true,
    viewport: { width: 1280, height: 800 },
  });
  const page = await ctx.newPage();
  page.on("dialog", async (d) => {
    dialogs.push({ type: d.type(), message: d.message(), ts: new Date().toISOString() });
    try {
      await d.accept();
    } catch (_) {}
  });

  let navError = null;
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 });
  } catch (e) {
    navError = String(e);
  }
  await page.waitForTimeout(waitMs);

  let sink = null;
  if (selector) {
    try {
      sink = await page.evaluate((sel) => {
        const el = document.querySelector(sel);
        if (!el) return { found: false, selector: sel };
        return {
          found: true,
          selector: sel,
          innerHTML: el.innerHTML,
          textContent: (el.textContent || "").slice(0, 500),
        };
      }, selector);
    } catch (e) {
      sink = { found: false, error: String(e) };
    }
  }

  const shot = path.join(caseDir, "screenshot.png");
  await page.screenshot({ path: shot, fullPage: false });
  const htmlPath = path.join(caseDir, "page.html");
  try {
    fs.writeFileSync(htmlPath, await page.content());
  } catch (_) {}

  const domain = await page.evaluate(() => document.domain).catch(() => null);
  await browser.close();

  const executed = dialogs.length > 0;
  const meta = {
    name,
    ts: new Date().toISOString(),
    recorder: "artex-recorder/2",
    recorder_seq: `${Date.now()}-${process.pid}-${require("crypto").randomBytes(6).toString("hex")}`,
    url,
    dialogs,
    dialog_executed: executed,
    document_domain: domain,
    sink,
    nav_error: navError,
    files: { screenshot: shot, page_html: htmlPath },
    checks: [
      {
        name: "js_executed_dialog",
        pass: executed,
        expected: "alert/confirm/prompt fired",
        actual: dialogs,
      },
    ],
    checks_pass: executed,
  };
  fs.writeFileSync(path.join(caseDir, "meta.json"), JSON.stringify(meta, null, 2) + "\n");

  const packPath = path.join(path.resolve(outdir), "pack.json");
  let pack = { cases: [] };
  if (fs.existsSync(packPath)) {
    try {
      pack = JSON.parse(fs.readFileSync(packPath, "utf8"));
    } catch (_) {}
  }
  pack.cases = (pack.cases || []).filter((c) => c.name !== name);
  pack.cases.push({
    name,
    kind: "browser-xss",
    url,
    dialog_executed: executed,
    dialogs,
    dir: caseDir,
  });
  pack.updated_at = new Date().toISOString();
  fs.writeFileSync(packPath, JSON.stringify(pack, null, 2) + "\n");

  // 封印失败必须让整个记录失败：旧实现忽略 spawnSync 的退出码，未封印的证据
  // 看起来「已记录」，直到跑闸门才暴露。
  const sealErrors = [];
  try {
    const { spawnSync } = require("child_process");
    const fsTok = "/usr/local/share/artex-src/.recorder-token";
    let tok = "";
    try { tok = fs.readFileSync(fsTok, "utf8").trim(); } catch (_) {}
    const env = { ...process.env };
    if (tok) env.ARTEX_EVIDENCE_RECORDER_TOKEN = tok;
    else sealErrors.push("缺少记录器令牌文件：证据无法封印");
    if (tok) {
      for (const args of [
        ["seal", "--case-dir", caseDir],
        ["seal-pack", "--outdir", path.resolve(outdir)],
      ]) {
        const r = spawnSync("python3", ["/usr/local/share/artex-src/evidence_seal.py", ...args], {
          stdio: "pipe",
          env,
          encoding: "utf8",
        });
        if (r.status !== 0) {
          sealErrors.push(`evidence_seal ${args[0]} 失败: ${(r.stderr || r.stdout || "").trim().slice(0, 300)}`);
        }
      }
    }
  } catch (e) {
    sealErrors.push(`seal 调用失败: ${String(e)}`);
  }

  if (sealErrors.length) {
    console.error(JSON.stringify({ ok: false, seal_errors: sealErrors }, null, 2));
  }
  console.log(JSON.stringify({ ...meta, ...(sealErrors.length ? { seal_errors: sealErrors } : {}) }, null, 2));
  process.exit(sealErrors.length ? 3 : executed ? 0 : 1);
})().catch((e) => {
  console.error(String(e));
  process.exit(1);
});
