import { type Page, expect } from '@playwright/test';
import { ScanPage } from '../pages/scan.page';
import { FindingsPage } from '../pages/findings.page';

// Our own dummy targets, never third-party assets (persona BH-P05).
export const DUMMY_IN_SCOPE = 'demo.test\n*.demo.test';
export const DUMMY_OUT_SCOPE = 'admin.demo.test';

/**
 * Run a single MOCK-engine scan for `program` using dummy targets, then
 * return once the run finishes. Deterministic and with no network.
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

/** Confirm all of a program's findings (via bulk action), ready for the draft report. */
export async function confirmAllFindings(page: Page, program: string) {
  const findings = new FindingsPage(page);
  await findings.goto(program);
  await findings.selectAllVisible();
  await findings.bulk('Confirm');
  await expect(page.locator('.pill.st-confirmed').first()).toBeVisible();
}
