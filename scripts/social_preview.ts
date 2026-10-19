/**
 * Social preview image 1280x640 (spec 17.3): rendered from an HTML template with Playwright -
 * logo/word mark, claim and a section of the overview screenshot. Run after scripts/screenshots.ts.
 *
 *   node scripts/social_preview.ts
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { chromium } from "@playwright/test";

const ROOT = resolve(import.meta.dirname, "..");
const images = join(ROOT, "docs", "images");
const logo = readFileSync(join(images, "logo.svg"), "utf8");
const dashboard = readFileSync(join(images, "case-overview-dark.png")).toString("base64");
const inter = readFileSync(join(ROOT, "frontend", "public", "fonts", "Inter-Bold.woff2")).toString("base64");
const interRegular = readFileSync(join(ROOT, "frontend", "public", "fonts", "Inter-Regular.woff2")).toString("base64");

const html = `<!doctype html>
<html><head><meta charset="utf-8"><style>
@font-face { font-family: Inter; font-weight: 700; src: url(data:font/woff2;base64,${inter}) format("woff2"); }
@font-face { font-family: Inter; font-weight: 400; src: url(data:font/woff2;base64,${interRegular}) format("woff2"); }
html, body { margin: 0; width: 1280px; height: 640px; overflow: hidden; background: #0c1016; font-family: Inter, sans-serif; }
.wrap { position: relative; width: 1280px; height: 640px; }
.text { position: absolute; left: 72px; top: 88px; width: 560px; color: #e5ebf1; }
.mark { display: flex; align-items: center; gap: 18px; }
.mark svg { width: 76px; height: 76px; }
h1 { font-size: 58px; margin: 0; letter-spacing: -1px; }
p { font-size: 27px; line-height: 1.4; color: #9cabbb; margin: 32px 0 0; }
.tags { margin-top: 36px; display: flex; gap: 10px; flex-wrap: wrap; }
.tags span { font-size: 17px; padding: 6px 12px; border-radius: 8px; background: #10303a; color: #4cc3cd; }
.shot { position: absolute; right: -120px; top: 70px; width: 720px; border-radius: 14px; border: 1px solid #283340;
  box-shadow: 0 30px 80px rgba(0,0,0,.55); transform: perspective(1400px) rotateY(-14deg); }
</style></head>
<body><div class="wrap">
  <img class="shot" src="data:image/png;base64,${dashboard}" alt="">
  <div class="text">
    <div class="mark">${logo}<h1>SentinelOps</h1></div>
    <p>Erklärbares, KI-gestütztes Security-Operations-Werkzeug: von 50.000 Log-Zeilen zum untersuchbaren Fall</p>
    <div class="tags"><span>Sigma-Regeln</span><span>Belege statt Behauptungen</span><span>Mensch entscheidet</span></div>
  </div>
</div></body></html>`;

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 640 }, deviceScaleFactor: 1 });
await page.setContent(html, { waitUntil: "load" });
await page.evaluate(() => document.fonts.ready);
writeFileSync(join(images, "social-preview.png"), await page.screenshot());
await browser.close();
console.log("wrote docs/images/social-preview.png");
