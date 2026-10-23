import { test, expect } from '../fixtures/test';
import { runMockScan, confirmAllFindings } from '../utils/seed';
import { ReportPage } from '../pages/report.page';

// SKENARIO KRITIS #2 — tidak ada auto-submit. Report selalu berakhir sebagai
// draft dengan ekspor manual; tidak ada jalur kirim otomatis ke platform.
test('KRITIS: report draft tanpa auto-submit', async ({ page }) => {
  const program = 'e2e-nosubmit';
  await runMockScan(page, program);
  await confirmAllFindings(page, program);

  const report = new ReportPage(page);
  await report.goto(program);

  // Draft + ekspor manual tersedia.
  await expect(page.getByText('DRAFT', { exact: true })).toBeVisible();
  await expect(report.downloadMd()).toBeVisible();
  await expect(report.printPdf()).toBeVisible();
  await expect(page.getByText(/tidak ada tombol submit/i)).toBeVisible();

  // Tidak ada satu pun kontrol kirim/submit otomatis.
  await expect(report.submitLikeControls()).toHaveCount(0);

  // Pengaman kebocoran: secret dari evidence engine tidak muncul mentah.
  await expect(page.getByText('SECRET-abc123')).toHaveCount(0);
});
