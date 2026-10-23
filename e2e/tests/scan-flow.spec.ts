import { test, expect } from '../fixtures/test';
import { ScanPage } from '../pages/scan.page';
import { FindingsPage } from '../pages/findings.page';

// Happy-path: konfigurasi scan → jalankan (engine mock) → selesai → temuan
// muncul di Findings. Target luar scope di set yang sama ditolak di UI.
test('scan happy-path (engine mock): jalankan, selesai, temuan muncul', async ({ page }) => {
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

  // Ada temuan baru, dan target luar scope (evil.test) ditolak scope guard.
  await expect(scan.savedChip()).toBeVisible();
  await expect(scan.deniedHeading()).toBeVisible();
  await expect(scan.result.getByText('evil.test')).toBeVisible();

  // Lanjut ke Findings: temuan mock deterministik terlihat.
  await scan.openFindings();
  const findings = new FindingsPage(page);
  await expect(findings.rows().first()).toBeVisible();
  await expect(page.getByText('SSRF via fetch parameter')).toBeVisible();
  await expect(page.getByText('Exposed .env configuration file')).toBeVisible();
});
