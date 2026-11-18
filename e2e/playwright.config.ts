import { defineConfig, devices } from '@playwright/test';
import path from 'node:path';

// E2E-only port (avoid clashing with the dev instance on 8787).
const PORT = Number(process.env.BH_E2E_PORT ?? 8799);
const BASE_URL = `http://127.0.0.1:${PORT}`;
const ROOT = path.resolve(__dirname, '..');
const isWin = process.platform === 'win32';
// The binary is built by global-setup (see global-setup.ts) into the repo root.
// Use an absolute path (quoted) to stay clear of shell cwd/PATH resolution.
const BIN_ABS = path.join(ROOT, isWin ? 'bughound-e2e.exe' : 'bughound-e2e');

export default defineConfig({
  testDir: './tests',
  // Determinism over speed: one shared server + in-memory store,
  // each test separated by a unique program name, run serially.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : [['list'], ['html', { open: 'never' }]],
  timeout: 30_000,
  expect: { timeout: 7_000 },

  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    // The app is desktop-optimized; Chromium is enough for the happy path.
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],

  webServer: {
    // Build then run in one command. globalSetup is NOT used: Playwright
    // starts webServer BEFORE globalSetup, so the binary has to be built
    // here. The build only compiles from the module cache (no network), so
    // the dead proxy env below does not get in the way; in CI the module
    // cache is warmed first (.github/workflows/e2e.yml).
    // Engines are MOCK, the store & keys are ephemeral in-memory, bound to
    // localhost, so no file (db/keys) is left behind and the network is never touched.
    // -no-auth: E2E verifies the product flow straight on the page; login & RBAC
    // are covered by Go unit tests (internal/web). Still mock engines + localhost,
    // so no network is touched.
    command:
      `go build -trimpath -o "${BIN_ABS}" ./cmd/bughound && ` +
      `"${BIN_ABS}" -addr 127.0.0.1:${PORT} -db "" -key "" -engine mock -no-auth`,
    cwd: ROOT,
    url: `${BASE_URL}/scan`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    stdout: 'pipe',
    stderr: 'pipe',
    env: {
      // Environment-level egress guard: point any outbound at a dead proxy so
      // an outgoing connection fails (rather than actually leaving). The mock
      // engines never egress anyway, so this is defense-in-depth.
      HTTP_PROXY: 'http://127.0.0.1:1',
      HTTPS_PROXY: 'http://127.0.0.1:1',
      ALL_PROXY: 'http://127.0.0.1:1',
      NO_PROXY: '127.0.0.1,localhost',
    },
  },
});
