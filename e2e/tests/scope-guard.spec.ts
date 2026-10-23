import { test, expect } from '../fixtures/test';
import { ScopeEditorPage } from '../pages/scope-editor.page';

// SKENARIO KRITIS #1 — scope guard menolak target di luar scope, terlihat di UI
// SEBELUM scan berjalan. Diuji lewat pratinjau scope editor (tanpa jaringan).
test('KRITIS: scope guard menolak target luar scope (pratinjau, tanpa scan)', async ({ page }) => {
  const editor = new ScopeEditorPage(page);
  await editor.gotoNew();
  await editor.fill({
    name: 'e2e-scope',
    inScope: 'demo.test\n*.demo.test',
    outScope: 'admin.demo.test',
    targets: 'app.demo.test\nadmin.demo.test\nevil.test',
  });
  await editor.clickPreview();

  // in-scope → izin
  await expect(editor.previewRow('app.demo.test').getByText('izin')).toBeVisible();
  // out-of-scope menang atas in-scope → tolak
  await expect(editor.previewRow('admin.demo.test').getByText('tolak')).toBeVisible();
  // tidak cocok scope apa pun → default-deny → tolak
  await expect(editor.previewRow('evil.test').getByText('tolak')).toBeVisible();
});
