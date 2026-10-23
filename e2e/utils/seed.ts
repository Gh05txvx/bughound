import { type Page, expect } from '@playwright/test';
import { ScanPage } from '../pages/scan.page';
import { FindingsPage } from '../pages/findings.page';

// Target dummy milik sendiri — tidak pernah aset pihak ketiga (persona BH-P05).
export const DUMMY_IN_SCOPE = 'demo.test\n*.demo.test';
export const DUMMY_OUT_SCOPE = 'admin.demo.test';

/**
 * Jalankan satu scan engine-MOCK untuk `program` memakai target dummy, lalu
 * kembali setelah run selesai. Deterministik dan tanpa jaringan.
 */
export async function runMockScan(page: Page, program: string, targets: string[] = ['demo.test']) {
  const scan = new ScanPage(page);
  await scan.goto();
  await scan.fill({
    program,
    seeds: '',
    inScope: DUMMY_IN_SCOPE,
    outScope: DUMMY_OUT_SCOPE,
    targets: targets.join('\n'),
  });
  await scan.run();
  await scan.waitForDone();
}

/** Konfirmasi semua temuan program (via aksi massal), siap masuk draft report. */
export async function confirmAllFindings(page: Page, program: string) {
  const findings = new FindingsPage(page);
  await findings.goto(program);
  await findings.selectAllVisible();
  await findings.bulk('Konfirmasi');
  await expect(page.locator('.pill.st-confirmed').first()).toBeVisible();
}
