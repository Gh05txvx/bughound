import { test, expect } from '../fixtures/test';
import { ScopeEditorPage } from '../pages/scope-editor.page';

// The dummy uses example.com, not *.test: the importer deliberately rejects an
// unknown TLD. No connection: convert & preview run purely on the local server.
const HEADER =
  'identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,' +
  'availability_requirement,confidentiality_requirement,integrity_requirement,' +
  'max_severity,system_tags,created_at,updated_at\n';
const row = (id: string, submit: string) => `${id},URL,,true,${submit},,,,critical,,,\n`;

// Import fills the form for review; a new scope is saved only via Save.
test('import scope: review, preview, saved only via Save scope', async ({ page }) => {
  const editor = new ScopeEditorPage(page);
  await editor.gotoNew();
  await page.locator('input[name="name"]').fill('e2e-import');
  await editor.importData(HEADER + row('*.example.com', 'true') + row('admin.example.com', 'false'));

  await expect(page.getByRole('heading', { name: /Import result/ })).toBeVisible();
  await expect(page.getByText('Not saved yet')).toBeVisible();
  await expect(editor.inScope).toHaveValue('*.example.com');
  await expect(editor.outScope).toHaveValue('admin.example.com');

  // Not saved yet: the program is not in the list.
  await page.goto('/programs');
  await expect(page.getByRole('cell', { name: 'e2e-import', exact: true })).toHaveCount(0);

  // Repeat, test with preview, then save.
  await editor.gotoNew();
  await page.locator('input[name="name"]').fill('e2e-import');
  await editor.importData(HEADER + row('*.example.com', 'true') + row('admin.example.com', 'false'));
  await editor.targets.fill('www.example.com\nadmin.example.com');
  await editor.clickPreview();
  await expect(editor.previewRow('www.example.com').getByText('allow')).toBeVisible();
  await expect(editor.previewRow('admin.example.com').getByText('deny')).toBeVisible();

  await editor.save();
  await expect(page).toHaveURL(/\/programs$/);
  await expect(page.getByRole('cell', { name: 'e2e-import', exact: true })).toBeVisible();
});

// An exclusion that cannot be represented holds the import until the user acknowledges it.
test('import scope: an unrepresentable exclusion holds the import', async ({ page }) => {
  const editor = new ScopeEditorPage(page);
  await editor.gotoNew();
  await page.locator('input[name="name"]').fill('e2e-import-held');
  await editor.importData(HEADER + row('app.example.com', 'true') + row('support.example.*', 'false'));

  await expect(page.getByRole('heading', { name: /Import held/ })).toBeVisible();
  await expect(page.locator('.errors').getByText('support.example.*')).toBeVisible();
  await expect(editor.inScope).toHaveValue('');

  // Without the checkbox, it stays held.
  await page.getByRole('button', { name: 'Continue import' }).click();
  await expect(page.getByRole('heading', { name: /Import held/ })).toBeVisible();
  await expect(editor.inScope).toHaveValue('');

  await page.getByLabel(/I have read this list/).check();
  await page.getByRole('button', { name: 'Continue import' }).click();
  await expect(page.getByRole('heading', { name: /Import result/ })).toBeVisible();
  await expect(editor.inScope).toHaveValue('app.example.com');
});

// Out-of-scope wins: an in-scope entry a wildcard overrides must be reported.
test('import scope: an in-scope entry an exclusion overrides is reported', async ({ page }) => {
  const editor = new ScopeEditorPage(page);
  await editor.gotoNew();
  await editor.importData(HEADER + row('www.example.com', 'true') + row('*.example.com', 'false'));

  const report = page.locator('.import-report');
  await expect(report.getByText('In-scope entries overridden by an exclusion (1)')).toBeVisible();
  await expect(report.getByText('denied by *.example.com')).toBeVisible();
});

// The file is loaded in the browser into the textarea, so its content can be reviewed before sending.
test('import scope: a CSV file loads into the textarea', async ({ page }) => {
  const editor = new ScopeEditorPage(page);
  await editor.gotoNew();
  const csv = HEADER + row('app.example.com', 'true');

  await editor.openImport();
  await page.getByLabel('Load scope file').setInputFiles({
    name: 'scope.csv',
    mimeType: 'text/csv',
    buffer: Buffer.from(csv),
  });
  await expect(editor.platformData).toHaveValue(csv);

  await page.getByRole('button', { name: 'Convert to scope' }).click();
  await expect(editor.inScope).toHaveValue('app.example.com');
});
