import { test, expect } from '../fixtures/test';
import { ScopeEditorPage } from '../pages/scope-editor.page';

// CRITICAL SCENARIO #1: the scope guard denies an out-of-scope target, visible in the UI
// BEFORE the scan runs. Tested via the scope editor preview (no network).
test('CRITICAL: scope guard denies an out-of-scope target (preview, no scan)', async ({ page }) => {
  const editor = new ScopeEditorPage(page);
  await editor.gotoNew();
  await editor.fill({
    name: 'e2e-scope',
    inScope: 'demo.test\n*.demo.test',
    outScope: 'admin.demo.test',
    targets: 'app.demo.test\nadmin.demo.test\nevil.test',
  });
  await editor.clickPreview();

  // in-scope -> allow
  await expect(editor.previewRow('app.demo.test').getByText('allow')).toBeVisible();
  // out-of-scope beats in-scope -> deny
  await expect(editor.previewRow('admin.demo.test').getByText('deny')).toBeVisible();
  // matches no scope at all -> default-deny -> deny
  await expect(editor.previewRow('evil.test').getByText('deny')).toBeVisible();
});
