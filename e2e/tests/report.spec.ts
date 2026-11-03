import fs from 'node:fs';
import { type Page, type Locator } from '@playwright/test';
import { test, expect } from '../fixtures/test';
import { runMockScan } from '../utils/seed';
import { FindingsPage } from '../pages/findings.page';
import { ReportPage } from '../pages/report.page';

// Alur M3 (lengkapi draft → report → ekspor). Hunter mengisi langkah reproduksi
// & dampak pada sebuah temuan, mengonfirmasinya, lalu draft report DAN ekspor
// platform (HackerOne/Bugcrowd) memuat repro + dampak yang diisi — bukan
// placeholder. Semua lewat engine MOCK; tanpa scan nyata (persona BH-P05-E2E).

const DESC = 'E2E-DESKRIPSI: parameter fetch menerima URL tanpa validasi (SSRF).';
const REPRO = [
  'E2E-REPRO-1: kirim GET /fetch?url=http://169.254.169.254/latest/meta-data/',
  'E2E-REPRO-2: amati respons memuat metadata internal',
];
const IMPACT = 'E2E-DAMPAK: penyerang membaca metadata internal cloud.';

/** Klik tautan unduhan (attachment) → tangkap unduhan → baca isinya sebagai teks. */
async function downloadText(page: Page, link: Locator): Promise<string> {
  const [download] = await Promise.all([page.waitForEvent('download'), link.click()]);
  const p = await download.path();
  expect(p, 'unduhan harus tersimpan ke file lokal').toBeTruthy();
  return fs.readFileSync(p as string, 'utf8');
}

test('M3: lengkapi draft (repro+dampak) → report & ekspor terisi', async ({ page }) => {
  const program = 'e2e-report-draft';
  await runMockScan(page, program);

  // 1) Buka temuan SSRF (critical) lalu lengkapi draft-nya lewat form detail.
  const findings = new FindingsPage(page);
  await findings.goto(program);
  await findings.open('SSRF via fetch parameter');

  const detail = findings.detail();
  const edit = detail.locator('form.edit');
  await edit.getByLabel('Deskripsi').fill(DESC);
  await edit.getByLabel(/Langkah reproduksi/).fill(REPRO.join('\n'));
  await edit.getByLabel('Dampak').fill(IMPACT);
  await edit.getByRole('button', { name: 'Simpan draft' }).click();

  // Draft tersimpan: detail ter-render ulang dengan nilai dampak yang baru.
  await expect(detail.locator('textarea[name="impact"]')).toHaveValue(IMPACT);

  // 2) Konfirmasi temuan agar masuk draft report.
  await detail.getByRole('button', { name: 'Konfirmasi', exact: true }).click();
  await expect(detail.locator('.pill.st-confirmed')).toBeVisible();
  await detail.getByRole('link', { name: /Lihat draft report/ }).click();

  // 3) Halaman report: temuan terkonfirmasi tampil dengan deskripsi draft.
  const report = new ReportPage(page);
  await expect(page).toHaveURL(new RegExp(`/report\\?program=${program}`));
  await expect(page.getByText('DRAFT', { exact: true })).toBeVisible();
  await expect(page.locator('.report-item').getByText(DESC)).toBeVisible();

  // 4a) Draft .md internal (report.go) memuat langkah reproduksi + dampak.
  const draftMd = await downloadText(page, report.downloadMd());
  expect(draftMd).toContain('Langkah reproduksi');
  expect(draftMd).toContain(REPRO[0]);
  expect(draftMd).toContain('Dampak:');
  expect(draftMd).toContain(IMPACT);

  // 4b) Ekspor platform (export.go) memuat repro + dampak yang diisi hunter.
  const h1 = await downloadText(page, report.exportLink('HackerOne'));
  expect(h1).toContain('Steps To Reproduce');
  expect(h1).toContain(REPRO[0]);
  expect(h1).toContain('## Impact');
  expect(h1).toContain(IMPACT);

  const bc = await downloadText(page, report.exportLink('Bugcrowd'));
  expect(bc).toContain('Steps to Reproduce');
  expect(bc).toContain(REPRO[1]);
  expect(bc).toContain(IMPACT);

  // 5) Pengaman: tetap draft, tanpa kontrol submit, tanpa bocor secret engine.
  await expect(report.submitLikeControls()).toHaveCount(0);
  await expect(page.getByText('SECRET-abc123')).toHaveCount(0);
});
