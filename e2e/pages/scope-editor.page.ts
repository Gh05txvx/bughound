import { type Page, type Locator } from '@playwright/test';

/** Scope editor: create/change a program scope definition + preview allow/deny. */
export class ScopeEditorPage {
  readonly preview: Locator;
  readonly inScope: Locator;
  readonly outScope: Locator;
  readonly targets: Locator;
  readonly platformData: Locator;
  constructor(private readonly page: Page) {
    this.preview = page.locator('#preview');
    this.inScope = page.locator('textarea[name="in_scope"]');
    this.outScope = page.locator('textarea[name="out_scope"]');
    this.targets = page.locator('textarea[name="targets"]');
    this.platformData = page.locator('textarea[name="platform_data"]');
  }

  async gotoNew() {
    await this.page.goto('/programs/edit');
  }

  async gotoEdit(name: string) {
    await this.page.goto(`/programs/edit?name=${encodeURIComponent(name)}`);
  }

  async fill(opts: { name?: string; inScope: string; outScope?: string; targets?: string }) {
    if (opts.name !== undefined) await this.page.locator('input[name="name"]').fill(opts.name);
    await this.page.locator('textarea[name="in_scope"]').fill(opts.inScope);
    await this.page.locator('textarea[name="out_scope"]').fill(opts.outScope ?? '');
    await this.page.locator('textarea[name="targets"]').fill(opts.targets ?? '');
  }

  /** Preview the scope decisions (HTMX, without touching the network). */
  async clickPreview() {
    await this.page.getByRole('button', { name: 'Preview' }).click();
  }

  async save() {
    await this.page.getByRole('button', { name: 'Save scope' }).click();
  }

  /** Open the platform import panel. */
  async openImport() {
    await this.page.getByText('Import from a platform').click();
  }

  /** Paste platform scope data then convert (fills the form, does not save). */
  async importData(data: string) {
    await this.openImport();
    await this.platformData.fill(data);
    await this.page.getByRole('button', { name: 'Convert to scope' }).click();
  }

  /** The preview row for one target (an exact match on the target cell). */
  previewRow(target: string): Locator {
    return this.preview.locator('table tbody tr', {
      has: this.page.getByText(target, { exact: true }),
    });
  }
}
