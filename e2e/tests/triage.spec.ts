import { test, expect } from '../fixtures/test';
import { runMockScan } from '../utils/seed';
import { FindingsPage } from '../pages/findings.page';

// Triage: filter by severity, then confirm in bulk.
test('triage: filter by severity then confirm in bulk', async ({ page }) => {
  const program = 'e2e-triage';
  await runMockScan(page, program);

  const findings = new FindingsPage(page);
  await findings.goto(program);

  // Two mock findings: SSRF (critical) + .env (medium).
  await expect(page.getByText('SSRF via fetch parameter')).toBeVisible();
  await expect(page.getByText('Exposed .env configuration file')).toBeVisible();

  // Filter severity=critical -> only SSRF shows.
  await findings.filter({ severity: 'critical' });
  await expect(page.getByText('SSRF via fetch parameter')).toBeVisible();
  await expect(page.getByText('Exposed .env configuration file')).toHaveCount(0);

  // Confirm the filtered findings in bulk.
  await findings.selectAllVisible();
  await findings.bulk('Confirm');
  await expect(page.locator('.pill.st-confirmed').first()).toBeVisible();
});
