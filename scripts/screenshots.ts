/**
 * Reproducible README/docs images (spec 17.3). Never edit the images by hand.
 *
 *   node scripts/screenshots.ts            # write docs/images/*.png and docs/images/demo.gif
 *   node scripts/screenshots.ts --check    # render to .cache/ and compare with the committed images
 *
 * Starts a fresh demo instance (scripts/e2e_server.py, seed "dev", fixed demo clock) unless
 * SCREENSHOT_BASE_URL points to a running one. Requires SENTINELOPS_E2E_ADMIN_URL for the database.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { chromium, type Browser, type Page } from "@playwright/test";
import gifenc from "gifenc"; // CommonJS module: named exports via the default export

const { applyPalette, GIFEncoder, quantize } = gifenc;
import { PNG } from "pngjs";

const ROOT = resolve(import.meta.dirname, "..");
const CHECK = process.argv.includes("--check");
const GIF_ONLY = process.argv.includes("--gif-only");
const OUT = CHECK ? join(ROOT, ".cache", "screenshots") : join(ROOT, "docs", "images");
const MAX_BYTES = 600 * 1024; // per image (spec 17.3)
const MAX_GIF_BYTES = 8 * 1024 * 1024;
const MAX_DIFF = 0.005; // 0.5 % of the pixels
const VIEWPORT = { width: 1440, height: 900 };
const CASE = "Aufnahme in privilegierte Gruppe: jonas.becker"; // scenario 2

type Theme = "dark" | "light";
type DemoUser = "analyst" | "senior" | "engineer" | "admin" | "auditor";

async function waitForHealth(url: string, timeoutMs: number): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(`${url}/api/v1/health`);
      if (response.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`demo instance at ${url} did not become healthy`);
}

function startServer(port: string): ChildProcess {
  const child = spawn("uv", ["run", "--directory", "backend", "python", "../scripts/e2e_server.py"], {
    cwd: ROOT,
    env: { ...process.env, E2E_PORT: port, SENTINELOPS_E2E_DB: "sentinelops_screens" },
    stdio: "inherit",
  });
  return child;
}

async function newPage(browser: Browser, base: string, theme: Theme, scale = 2): Promise<Page> {
  const context = await browser.newContext({
    baseURL: base,
    viewport: VIEWPORT,
    deviceScaleFactor: scale,
    colorScheme: theme,
    locale: "de-DE",
    timezoneId: "Europe/Berlin",
    reducedMotion: "reduce",
  });
  await context.addInitScript((value) => {
    window.localStorage.setItem("sentinelops.theme", value);
    window.localStorage.setItem("sentinelops.language", "de");
  }, theme);
  return context.newPage();
}

async function login(page: Page, user: DemoUser): Promise<void> {
  await page.goto("/");
  await page.getByTestId(`demo-login-${user}`).click();
  await page.getByRole("navigation", { name: "Hauptnavigation" }).first().waitFor();
}

async function settle(page: Page): Promise<void> {
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => document.fonts.ready);
  await page.mouse.move(0, 0);
  await page.waitForTimeout(300);
}

async function openCase(page: Page): Promise<string> {
  await page.goto("/cases");
  await page.getByRole("link", { name: CASE }).first().click();
  await page.getByRole("heading", { level: 1, name: CASE }).waitFor();
  const id = /\/cases\/([0-9a-f]+)/.exec(page.url())?.[1];
  if (!id) throw new Error("case id not found");
  return id;
}

/** Make sure the scenario-2 case has a proposed action (for the approval dialog). */
async function ensureProposal(browser: Browser, base: string): Promise<void> {
  const page = await newPage(browser, base, "dark", 1);
  await login(page, "analyst");
  await openCase(page);
  const pending = page.getByTestId("actions-list").locator("li[data-status='proposed']");
  if ((await pending.count()) === 0) {
    await page.locator("li", { hasText: "DISABLE_ACCOUNT" }).first().getByRole("button", { name: "Maßnahme vorschlagen" }).click();
    await page.getByRole("dialog").getByLabel("Begründung").fill(
      "Konto nach erfolgreicher Brute-Force-Anmeldung und Aufnahme in Domänen-Admins kompromittiert",
    );
    await page.getByRole("dialog").getByRole("button", { name: "Vorschlag einreichen" }).click();
    await pending.first().waitFor();
  }
  await page.context().close();
}

const SHOTS: { name: string; user: DemoUser; go: (page: Page) => Promise<void>; full?: boolean }[] = [
  { name: "dashboard", user: "analyst", go: async (p) => { await p.goto("/"); } },
  { name: "queue", user: "analyst", go: async (p) => { await p.goto("/cases"); } },
  { name: "case-overview", user: "senior", go: async (p) => { await openCase(p); } },
  {
    name: "case-timeline",
    user: "analyst",
    go: async (p) => {
      await openCase(p);
      await p.getByRole("link", { name: /^Timeline/ }).click();
      await p.getByTestId("timeline-list").waitFor();
    },
  },
  {
    name: "case-evidence",
    user: "analyst",
    go: async (p) => {
      await openCase(p);
      await p.getByRole("link", { name: /^Belege/ }).click();
      await p.getByTestId("alert-evidence").first().waitFor();
      await p.getByTestId("alert-evidence").nth(3).scrollIntoViewIfNeeded();
    },
  },
  {
    name: "entity-graph",
    user: "analyst",
    go: async (p) => {
      await openCase(p);
      await p.getByRole("link", { name: /^Entitätsgraph/ }).click();
      await p.getByRole("img", { name: /Entitätsgraph/ }).waitFor();
    },
  },
  {
    name: "approval",
    user: "senior",
    go: async (p) => {
      await openCase(p);
      await p.getByTestId("actions-list").locator("li[data-status='proposed']").first()
        .getByRole("button", { name: "Prüfen und entscheiden" }).click();
      await p.getByTestId("approval-dialog").getByLabel("Begründung der Entscheidung (Pflicht)").fill(
        "Belege E41–E43 eindeutig, Rückruf beim Kontoinhaber ohne Erfolg",
      );
    },
  },
  { name: "rules", user: "engineer", go: async (p) => { await p.goto("/rules"); } },
  { name: "quality", user: "admin", go: async (p) => { await p.goto("/quality"); } },
  {
    name: "report",
    user: "analyst",
    go: async (p) => {
      await openCase(p);
      await p.getByRole("link", { name: /^Bericht/ }).click();
      await p.getByTestId("report-preview").waitFor();
    },
  },
];

function diffRatio(a: Buffer, b: Buffer): number {
  const x = PNG.sync.read(a);
  const y = PNG.sync.read(b);
  if (x.width !== y.width || x.height !== y.height) return 1;
  let differing = 0;
  for (let i = 0; i < x.data.length; i += 4) {
    const delta =
      Math.abs(x.data[i]! - y.data[i]!) + Math.abs(x.data[i + 1]! - y.data[i + 1]!) + Math.abs(x.data[i + 2]! - y.data[i + 2]!);
    if (delta > 24) differing += 1;
  }
  return differing / (x.width * x.height);
}

async function demoGif(browser: Browser, base: string): Promise<void> {
  const page = await newPage(browser, base, "dark", 1);
  await page.setViewportSize({ width: 1200, height: 750 });
  const frames: { png: Buffer; delay: number }[] = [];
  const capture = async (delay: number) => {
    await settle(page);
    frames.push({ png: await page.screenshot(), delay });
  };
  await login(page, "analyst");
  await capture(2200); // overview
  await page.goto("/cases");
  await capture(1800); // queue
  await page.getByRole("link", { name: CASE }).first().click();
  await capture(2600); // case with priority reasons
  await page.getByRole("link", { name: /^Timeline/ }).click();
  await capture(2200);
  await page.getByRole("link", { name: /^Belege/ }).click();
  await capture(2600);
  await page.getByRole("link", { name: /^Übersicht/ }).click();
  await page.locator("li", { hasText: "DISABLE_ACCOUNT" }).first().getByRole("button", { name: "Maßnahme vorschlagen" }).click();
  await page.getByRole("dialog").getByLabel("Begründung").fill("Konto kompromittiert");
  await capture(2600); // proposal dialog with simulation notice
  const gif = GIFEncoder();
  for (const frame of frames) {
    const image = PNG.sync.read(frame.png);
    const rgba = new Uint8Array(image.data.buffer, image.data.byteOffset, image.data.length);
    const palette = quantize(rgba, 256);
    gif.writeFrame(applyPalette(rgba, palette), image.width, image.height, { palette, delay: frame.delay });
  }
  gif.finish();
  writeFileSync(join(OUT, "demo.gif"), gif.bytes());
  await page.context().close();
}

async function main(): Promise<void> {
  mkdirSync(OUT, { recursive: true });
  const port = process.env.SCREENSHOT_PORT ?? "8002";
  let base = process.env.SCREENSHOT_BASE_URL;
  let server: ChildProcess | undefined;
  if (!base) {
    base = `http://127.0.0.1:${port}`;
    server = startServer(port);
  }
  const problems: string[] = [];
  try {
    await waitForHealth(base, 900_000);
    const browser = await chromium.launch();
    await ensureProposal(browser, base);
    for (const theme of GIF_ONLY ? [] : (["dark", "light"] as const)) {
      for (const shot of SHOTS) {
        const page = await newPage(browser, base, theme);
        await login(page, shot.user);
        await shot.go(page);
        await settle(page);
        const file = join(OUT, `${shot.name}-${theme}.png`);
        writeFileSync(file, await page.screenshot({ fullPage: shot.full ?? false }));
        const size = statSync(file).size;
        if (size > MAX_BYTES) problems.push(`${shot.name}-${theme}.png is ${Math.round(size / 1024)} kB (> 600 kB)`);
        if (CHECK) {
          const committed = join(ROOT, "docs", "images", `${shot.name}-${theme}.png`);
          if (!existsSync(committed)) problems.push(`missing committed image ${committed}`);
          else {
            const ratio = diffRatio(readFileSync(committed), readFileSync(file));
            if (ratio > MAX_DIFF) problems.push(`${shot.name}-${theme}.png differs by ${(ratio * 100).toFixed(2)} %`);
          }
        }
        console.log(`${shot.name}-${theme}.png ${Math.round(size / 1024)} kB`);
        await page.context().close();
      }
    }
    if (!CHECK) {
      await demoGif(browser, base);
      const gifSize = statSync(join(OUT, "demo.gif")).size;
      console.log(`demo.gif ${Math.round(gifSize / 1024)} kB`);
      if (gifSize > MAX_GIF_BYTES) problems.push(`demo.gif is larger than 8 MB`);
    }
    await browser.close();
  } finally {
    if (server?.pid) {
      // e2e_server.py starts uvicorn as a child: stop the whole process tree.
      if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(server.pid), "/T", "/F"]);
      else server.kill("SIGTERM");
    }
  }
  for (const problem of problems) console.error(problem);
  if (problems.length) process.exit(1);
}

await main();
