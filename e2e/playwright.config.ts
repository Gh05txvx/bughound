import { defineConfig, devices } from '@playwright/test';
import path from 'node:path';

// Port khusus E2E (hindari bentrok dengan instance dev 8787).
const PORT = Number(process.env.BH_E2E_PORT ?? 8799);
const BASE_URL = `http://127.0.0.1:${PORT}`;
const ROOT = path.resolve(__dirname, '..');
const isWin = process.platform === 'win32';
// Binary dibangun oleh global-setup (lihat global-setup.ts) ke root repo.
// Pakai path absolut (dikutip) agar lepas dari resolusi cwd/PATH shell.
const BIN_ABS = path.join(ROOT, isWin ? 'bughound-e2e.exe' : 'bughound-e2e');

export default defineConfig({
  testDir: './tests',
  // Determinisme di atas kecepatan: satu server + store in-memory dibagi,
  // tiap test dipisah oleh nama program unik, dijalankan serial.
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
    // Aplikasi dioptimalkan desktop; Chromium cukup untuk happy-path.
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],

  // Membangun binary dilakukan di global-setup (butuh jaringan untuk cache
  // modul), BUKAN di sini — agar proses server bisa dijalankan dengan egress
  // diblok tanpa mengganggu `go build`.
  globalSetup: require.resolve('./global-setup'),

  webServer: {
    // Binary sudah dibangun oleh global-setup. Engine MOCK, store in-memory
    // ephemeral, bind localhost. Tidak pernah menyentuh jaringan.
    // -db "" + -key "" → store & kunci in-memory ephemeral: tak ada file (db
    // atau kunci) yang tersisa di repo setelah test.
    command: `"${BIN_ABS}" -addr 127.0.0.1:${PORT} -db "" -key "" -engine mock`,
    cwd: ROOT,
    url: `${BASE_URL}/scan`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    stdout: 'pipe',
    stderr: 'pipe',
    env: {
      // Pengaman egress tingkat lingkungan: arahkan outbound apa pun ke proxy
      // mati sehingga koneksi keluar gagal (bukan benar-benar keluar). Engine
      // mock memang tak pernah egress — ini defense-in-depth.
      HTTP_PROXY: 'http://127.0.0.1:1',
      HTTPS_PROXY: 'http://127.0.0.1:1',
      ALL_PROXY: 'http://127.0.0.1:1',
      NO_PROXY: '127.0.0.1,localhost',
    },
  },
});
