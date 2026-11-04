import { test, expect } from '../fixtures/test';
import { ScopeEditorPage } from '../pages/scope-editor.page';

// Dummy memakai example.com, bukan *.test: importer sengaja menolak TLD tak
// dikenal. Tak ada koneksi: konversi & pratinjau murni di server lokal.
const HEADER =
  'identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,' +
  'availability_requirement,confidentiality_requirement,integrity_requirement,' +
  'max_severity,system_tags,created_at,updated_at\n';
const row = (id: string, submit: string) => `${id},URL,,true,${submit},,,,critical,,,\n`;

// Impor mengisi form untuk ditinjau; scope baru tersimpan hanya lewat Simpan.
test('impor scope: tinjau, pratinjau, baru tersimpan lewat Simpan scope', async ({ page }) => {
  const editor = new ScopeEditorPage(page);
  await editor.gotoNew();
  await page.locator('input[name="name"]').fill('e2e-import');
  await editor.importData(HEADER + row('*.example.com', 'true') + row('admin.example.com', 'false'));

  await expect(page.getByRole('heading', { name: /Hasil impor/ })).toBeVisible();
  await expect(page.getByText('Belum disimpan')).toBeVisible();
  await expect(editor.inScope).toHaveValue('*.example.com');
  await expect(editor.outScope).toHaveValue('admin.example.com');

  // Belum tersimpan: program belum ada di daftar.
  await page.goto('/programs');
  await expect(page.getByRole('cell', { name: 'e2e-import', exact: true })).toHaveCount(0);

  // Ulangi, uji dengan pratinjau, lalu simpan.
  await editor.gotoNew();
  await page.locator('input[name="name"]').fill('e2e-import');
  await editor.importData(HEADER + row('*.example.com', 'true') + row('admin.example.com', 'false'));
  await editor.targets.fill('www.example.com\nadmin.example.com');
  await editor.clickPreview();
  await expect(editor.previewRow('www.example.com').getByText('izin')).toBeVisible();
  await expect(editor.previewRow('admin.example.com').getByText('tolak')).toBeVisible();

  await editor.save();
  await expect(page).toHaveURL(/\/programs$/);
  await expect(page.getByRole('cell', { name: 'e2e-import', exact: true })).toBeVisible();
});

// Eksklusi yang tak bisa diwakili menahan impor sampai pengguna menyetujuinya.
test('impor scope: eksklusi tak terwakili menahan impor', async ({ page }) => {
  const editor = new ScopeEditorPage(page);
  await editor.gotoNew();
  await page.locator('input[name="name"]').fill('e2e-import-held');
  await editor.importData(HEADER + row('app.example.com', 'true') + row('support.example.*', 'false'));

  await expect(page.getByRole('heading', { name: /Impor ditahan/ })).toBeVisible();
  await expect(page.locator('.errors').getByText('support.example.*')).toBeVisible();
  await expect(editor.inScope).toHaveValue('');

  // Tanpa centang, tetap ditahan.
  await page.getByRole('button', { name: 'Lanjutkan impor' }).click();
  await expect(page.getByRole('heading', { name: /Impor ditahan/ })).toBeVisible();
  await expect(editor.inScope).toHaveValue('');

  await page.getByLabel(/sudah membaca daftar ini/).check();
  await page.getByRole('button', { name: 'Lanjutkan impor' }).click();
  await expect(page.getByRole('heading', { name: /Hasil impor/ })).toBeVisible();
  await expect(editor.inScope).toHaveValue('app.example.com');
});

// Out-of-scope menang: entri in-scope yang tertimpa wildcard harus dilaporkan.
test('impor scope: in-scope yang tertimpa eksklusi dilaporkan', async ({ page }) => {
  const editor = new ScopeEditorPage(page);
  await editor.gotoNew();
  await editor.importData(HEADER + row('www.example.com', 'true') + row('*.example.com', 'false'));

  const report = page.locator('.import-report');
  await expect(report.getByText('In-scope yang tertimpa eksklusi (1)')).toBeVisible();
  await expect(report.getByText('ditolak oleh *.example.com')).toBeVisible();
});

// Berkas dimuat di browser ke textarea, jadi isinya bisa ditinjau sebelum dikirim.
test('impor scope: berkas CSV termuat ke textarea', async ({ page }) => {
  const editor = new ScopeEditorPage(page);
  await editor.gotoNew();
  const csv = HEADER + row('app.example.com', 'true');

  await editor.openImport();
  await page.getByLabel('Muat berkas scope').setInputFiles({
    name: 'scope.csv',
    mimeType: 'text/csv',
    buffer: Buffer.from(csv),
  });
  await expect(editor.platformData).toHaveValue(csv);

  await page.getByRole('button', { name: 'Konversi ke scope' }).click();
  await expect(editor.inScope).toHaveValue('app.example.com');
});
