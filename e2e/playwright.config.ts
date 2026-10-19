import { defineConfig, devices } from "@playwright/test";

// The application under test is a fresh demo instance (scripts/e2e_server.py):
// fixed seed "dev", fixed demo clock, demo simulator for AI summaries.
//
// Every browser gets its OWN instance (database, port, dataset folder): the acceptance tests change
// data (A7 proposes, approves and executes an action), so browsers sharing one database would see
// each other's results. Ports: chromium 8001, firefox 8002, webkit 8003.
const python = process.env.E2E_PYTHON ?? "uv run --directory backend python";
const ci = Boolean(process.env.CI);
const basePort = Number(process.env.E2E_PORT ?? "8001");

const browsers = [
  { name: "chromium", device: devices["Desktop Chrome"] },
  ...(ci
    ? [
        { name: "firefox", device: devices["Desktop Firefox"] },
        { name: "webkit", device: devices["Desktop Safari"] },
      ]
    : []),
].map((browser, index) => ({ ...browser, port: basePort + index }));

/** URL of an already running instance: E2E_BASE_URL_<BROWSER>, or E2E_BASE_URL for chromium. */
function externalURL(name: string): string | undefined {
  const own = process.env[`E2E_BASE_URL_${name.toUpperCase()}`];
  if (own !== undefined && own !== "") return own;
  const shared = process.env.E2E_BASE_URL;
  return name === "chromium" && shared !== undefined && shared !== ""
    ? shared
    : undefined;
}

function baseURLFor(name: string, port: number): string {
  return externalURL(name) ?? `http://127.0.0.1:${String(port)}`;
}

// Instances are started here unless every browser already has a running one (CI starts them itself).
const external = browsers.every((b) => externalURL(b.name) !== undefined);

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.ts/,
  outputDir: "../.cache/e2e-results",
  snapshotPathTemplate:
    "{testDir}/__screenshots__/{platform}/{projectName}/{arg}{ext}",
  fullyParallel: false, // the tests of one browser share its database; they are written to be order independent
  workers: 1,
  retries: ci ? 1 : 0,
  timeout: 60_000,
  expect: {
    timeout: 10_000,
    toHaveScreenshot: { maxDiffPixelRatio: 0.002, animations: "disabled" },
  },
  reporter: ci
    ? [
        ["github"],
        ["html", { open: "never", outputFolder: "../.cache/e2e-report" }],
      ]
    : [["list"]],
  use: {
    locale: "de-DE",
    timezoneId: "Europe/Berlin",
    viewport: { width: 1440, height: 900 },
    trace: "retain-on-failure",
    colorScheme: "dark",
  },
  projects: browsers.map((b) => ({
    name: b.name,
    use: {
      ...b.device,
      viewport: { width: 1440, height: 900 },
      baseURL: baseURLFor(b.name, b.port),
    },
  })),
  webServer: external
    ? undefined
    : browsers.map((b) => ({
        command: `${python} ../scripts/e2e_server.py`,
        cwd: "..",
        url: `${baseURLFor(b.name, b.port)}/api/v1/health`,
        env: {
          E2E_PORT: String(b.port),
          SENTINELOPS_E2E_DB: `sentinelops_e2e_${b.name}`,
          E2E_DATASET: `.cache/e2e-dataset-${b.name}`,
        },
        timeout: 600_000,
        reuseExistingServer: !ci,
        stdout: "pipe" as const,
        stderr: "pipe" as const,
      })),
});
