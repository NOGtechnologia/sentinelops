import { defineConfig, devices } from "@playwright/test";

// The application under test is a fresh demo instance (scripts/e2e_server.py):
// fixed seed "dev", fixed demo clock, demo simulator for AI summaries.
const port = process.env.E2E_PORT ?? "8001";
const baseURL = process.env.E2E_BASE_URL ?? `http://127.0.0.1:${port}`;
const python = process.env.E2E_PYTHON ?? "uv run --directory backend python";
const ci = Boolean(process.env.CI);

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.ts/,
  outputDir: "../.cache/e2e-results",
  snapshotPathTemplate: "{testDir}/__screenshots__/{platform}/{projectName}/{arg}{ext}",
  fullyParallel: false, // tests share one database; they are written to be order independent
  workers: 1,
  retries: ci ? 1 : 0,
  timeout: 60_000,
  expect: { timeout: 10_000, toHaveScreenshot: { maxDiffPixelRatio: 0.002, animations: "disabled" } },
  reporter: ci ? [["github"], ["html", { open: "never", outputFolder: "../.cache/e2e-report" }]] : [["list"]],
  use: {
    baseURL,
    locale: "de-DE",
    timezoneId: "Europe/Berlin",
    viewport: { width: 1440, height: 900 },
    trace: "retain-on-failure",
    colorScheme: "dark",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } },
    ...(ci
      ? [
          { name: "firefox", use: { ...devices["Desktop Firefox"], viewport: { width: 1440, height: 900 } } },
          { name: "webkit", use: { ...devices["Desktop Safari"], viewport: { width: 1440, height: 900 } } },
        ]
      : []),
  ],
  webServer: process.env.E2E_BASE_URL
    ? undefined
    : {
        command: `${python} ../scripts/e2e_server.py`,
        cwd: "..",
        url: `${baseURL}/api/v1/health`,
        timeout: 600_000,
        reuseExistingServer: !ci,
        stdout: "pipe",
        stderr: "pipe",
      },
});
