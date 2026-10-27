import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "XFSRC",
  version: packageJson.version,
  copyright: `© ${currentYear}, XFSRC.`,
  meta: {
    title: "XFSRC — 授权 SRC 漏洞挖掘控制台",
    description: "面向授权 SRC 的 LLM 驱动漏洞挖掘平台（HackerOne / Intigriti / Bugcrowd）",
  },
};
