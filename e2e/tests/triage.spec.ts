import { test, expect } from '../fixtures/test';
import { runMockScan } from '../utils/seed';
import { FindingsPage } from '../pages/findings.page';

// Triase: filter berdasarkan severity, lalu konfirmasi massal.
test('triase: filter severity lalu konfirmasi massal', async ({ page }) => {
  const program = 'e2e-triage';
  await runMockScan(page, program);

  const findings = new FindingsPage(page);
  await findings.goto(program);

  // Dua temuan mock: SSRF (critical) + .env (medium).
  await expect(page.getByText('SSRF via fetch parameter')).toBeVisible();
  await expect(page.getByText('Exposed .env configuration file')).toBeVisible();

  // Filter severity=critical → hanya SSRF yang tampil.
  await findings.filter({ severity: 'critical' });
  await expect(page.getByText('SSRF via fetch parameter')).toBeVisible();
  await expect(page.getByText('Exposed .env configuration file')).toHaveCount(0);

  // Konfirmasi massal temuan yang tersaring.
  await findings.selectAllVisible();
  await findings.bulk('Konfirmasi');
  await expect(page.locator('.pill.st-confirmed').first()).toBeVisible();
});
