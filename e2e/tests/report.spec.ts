import fs from 'node:fs';
import { type Page, type Locator } from '@playwright/test';
import { test, expect } from '../fixtures/test';
import { runMockScan } from '../utils/seed';
import { FindingsPage } from '../pages/findings.page';
import { ReportPage } from '../pages/report.page';

// M3 flow (complete the draft -> report -> export). The hunter fills in the
// reproduction steps & impact on a finding, confirms it, then the draft report AND
// the platform export (HackerOne/Bugcrowd) carry the repro + impact that were
// filled in, not a placeholder. All via MOCK engines; no real scan (persona BH-P05-E2E).

const DESC = 'E2E-DESC: the fetch parameter accepts a URL with no validation (SSRF).';
const REPRO = [
  'E2E-REPRO-1: send GET /fetch?url=http://169.254.169.254/latest/meta-data/',
  'E2E-REPRO-2: watch the response carry the internal metadata',
];
const IMPACT = 'E2E-IMPACT: the attacker reads internal cloud metadata.';

/** Click a download link (attachment) -> capture the download -> read its content as text. */
async function downloadText(page: Page, link: Locator): Promise<string> {
  const [download] = await Promise.all([page.waitForEvent('download'), link.click()]);
  const p = await download.path();
  expect(p, 'the download must be saved to a local file').toBeTruthy();
  return fs.readFileSync(p as string, 'utf8');
}

test('M3: complete draft (repro+impact) so report & export are filled', async ({ page }) => {
  const program = 'e2e-report-draft';
  await runMockScan(page, program);

  // 1) Open the SSRF finding (critical) then complete its draft via the detail form.
  const findings = new FindingsPage(page);
  await findings.goto(program);
  await findings.open('SSRF via fetch parameter');

  const detail = findings.detail();
  const edit = detail.locator('form.edit');
  await edit.getByLabel('Description').fill(DESC);
  await edit.getByLabel(/Reproduction steps/).fill(REPRO.join('\n'));
  await edit.getByLabel('Impact').fill(IMPACT);
  await edit.getByRole('button', { name: 'Save draft' }).click();

  // The draft is saved: the detail re-renders with the new impact value.
  await expect(detail.locator('textarea[name="impact"]')).toHaveValue(IMPACT);

  // 2) Confirm the finding so it enters the draft report.
  await detail.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(detail.locator('.pill.st-confirmed')).toBeVisible();
  await detail.getByRole('link', { name: /View the draft report/ }).click();

  // 3) Report page: the confirmed finding shows with its draft description.
  const report = new ReportPage(page);
  await expect(page).toHaveURL(new RegExp(`/report\\?program=${program}`));
  await expect(page.getByText('DRAFT', { exact: true })).toBeVisible();
  await expect(page.locator('.report-item').getByText(DESC)).toBeVisible();

  // 4a) The internal draft .md (report.go) carries the reproduction steps + impact.
  const draftMd = await downloadText(page, report.downloadMd());
  expect(draftMd).toContain('Reproduction steps');
  expect(draftMd).toContain(REPRO[0]);
  expect(draftMd).toContain('Impact:');
  expect(draftMd).toContain(IMPACT);

  // 4b) The platform export (export.go) carries the repro + impact the hunter filled in.
  const h1 = await downloadText(page, report.exportLink('HackerOne'));
  expect(h1).toContain('Steps To Reproduce');
  expect(h1).toContain(REPRO[0]);
  expect(h1).toContain('## Impact');
  expect(h1).toContain(IMPACT);

  const bc = await downloadText(page, report.exportLink('Bugcrowd'));
  expect(bc).toContain('Steps to Reproduce');
  expect(bc).toContain(REPRO[1]);
  expect(bc).toContain(IMPACT);

  // 5) Guards: still a draft, no submit control, no engine secret leaked.
  await expect(report.submitLikeControls()).toHaveCount(0);
  await expect(page.getByText('SECRET-abc123')).toHaveCount(0);
});
