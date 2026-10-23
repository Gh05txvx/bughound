import { test, expect } from '../fixtures/test';
import { ProgramsPage } from '../pages/programs.page';
import { ScopeEditorPage } from '../pages/scope-editor.page';
import { ScanPage } from '../pages/scan.page';

// Buat program + atur scope → tersimpan → prefill form scan.
test('program & scope: buat, pratinjau, simpan, prefill scan', async ({ page }) => {
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

  // Pratinjau memperlihatkan keputusan sebelum menyimpan.
  await editor.clickPreview();
  await expect(editor.previewRow('www.acme.test').getByText('izin')).toBeVisible();
  await expect(editor.previewRow('secret.acme.test').getByText('tolak')).toBeVisible();

  // Simpan → kembali ke daftar, program tampil.
  await editor.save();
  await expect(page).toHaveURL(/\/programs$/);
  await expect(page.getByRole('cell', { name: 'e2e-prog', exact: true })).toBeVisible();

  // Form scan prefilled dari scope tersimpan.
  const scan = new ScanPage(page);
  await scan.goto('e2e-prog');
  await expect(page.locator('textarea[name="in_scope"]')).toHaveValue(/acme\.test/);
});
