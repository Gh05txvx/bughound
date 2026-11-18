import { test, expect } from '../fixtures/test';
import { ScanPage } from '../pages/scan.page';
import { FindingsPage } from '../pages/findings.page';

// Happy path: configure the scan -> run (mock engines) -> finish -> findings
// appear in Findings. An out-of-scope target in the same set is denied in the UI.
test('scan happy-path (mock engines): run, finish, findings appear', async ({ page }) => {
  const scan = new ScanPage(page);
  await scan.goto();
  await scan.fill({
    program: 'e2e-scan',
    seeds: '',
    inScope: 'demo.test\n*.demo.test',
    outScope: 'admin.demo.test',
    targets: 'demo.test\nevil.test',
  });
  await scan.run();
  await scan.waitForDone();

  // There are new findings, and the out-of-scope target (evil.test) is denied by the scope guard.
  await expect(scan.savedChip()).toBeVisible();
  await expect(scan.deniedHeading()).toBeVisible();
  await expect(scan.result.getByText('evil.test')).toBeVisible();

  // On to Findings: the deterministic mock finding is visible.
  await scan.openFindings();
  const findings = new FindingsPage(page);
  await expect(findings.rows().first()).toBeVisible();
  await expect(page.getByText('SSRF via fetch parameter')).toBeVisible();
  await expect(page.getByText('Exposed .env configuration file')).toBeVisible();
});
