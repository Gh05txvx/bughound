import { test, expect } from '../fixtures/test';
import { ProgramsPage } from '../pages/programs.page';
import { ScopeEditorPage } from '../pages/scope-editor.page';
import { ScanPage } from '../pages/scan.page';

// Create a program + set the scope -> saved -> prefill the scan form.
test('program & scope: create, preview, save, prefill scan', async ({ page }) => {
  const programs = new ProgramsPage(page);
  const editor = new ScopeEditorPage(page);

  await programs.goto();
  await programs.newProgram();
  await editor.fill({
    name: 'e2e-prog',
    inScope: 'acme.test\n*.acme.test',
    outScope: 'secret.acme.test',
    targets: 'www.acme.test\nsecret.acme.test',
  });

  // Preview shows the decisions before saving.
  await editor.clickPreview();
  await expect(editor.previewRow('www.acme.test').getByText('allow')).toBeVisible();
  await expect(editor.previewRow('secret.acme.test').getByText('deny')).toBeVisible();

  // Save -> back to the list, the program shows.
  await editor.save();
  await expect(page).toHaveURL(/\/programs$/);
  await expect(page.getByRole('cell', { name: 'e2e-prog', exact: true })).toBeVisible();

  // The scan form is prefilled from the saved scope.
  const scan = new ScanPage(page);
  await scan.goto('e2e-prog');
  await expect(page.locator('textarea[name="in_scope"]')).toHaveValue(/acme\.test/);
});
