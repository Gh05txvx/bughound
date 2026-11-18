import { test, expect } from '../fixtures/test';
import { runMockScan, confirmAllFindings } from '../utils/seed';
import { ReportPage } from '../pages/report.page';

// CRITICAL SCENARIO #2: no auto-submit. A report always ends as a
// draft with manual export; there is no automatic send path to a platform.
test('CRITICAL: draft report with no auto-submit', async ({ page }) => {
  const program = 'e2e-nosubmit';
  await runMockScan(page, program);
  await confirmAllFindings(page, program);

  const report = new ReportPage(page);
  await report.goto(program);

  // The draft + manual export are available.
  await expect(page.getByText('DRAFT', { exact: true })).toBeVisible();
  await expect(report.downloadMd()).toBeVisible();
  await expect(report.printPdf()).toBeVisible();
  await expect(page.getByText(/no submit button/i)).toBeVisible();

  // Not a single automatic send/submit control.
  await expect(report.submitLikeControls()).toHaveCount(0);

  // Leak guard: a secret from engine evidence does not show up raw.
  await expect(page.getByText('SECRET-abc123')).toHaveCount(0);
});
