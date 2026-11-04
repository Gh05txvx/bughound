import { type Page, type Locator } from '@playwright/test';

/** Scope editor: buat/ubah definisi scope program + pratinjau izin/tolak. */
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

  /** Pratinjau keputusan scope (HTMX, tanpa menyentuh jaringan). */
  async clickPreview() {
    await this.page.getByRole('button', { name: 'Pratinjau' }).click();
  }

  async save() {
    await this.page.getByRole('button', { name: 'Simpan scope' }).click();
  }

  /** Buka panel impor platform. */
  async openImport() {
    await this.page.getByText('Impor dari platform').click();
  }

  /** Tempel data scope platform lalu konversi (mengisi form, tidak menyimpan). */
  async importData(data: string) {
    await this.openImport();
    await this.platformData.fill(data);
    await this.page.getByRole('button', { name: 'Konversi ke scope' }).click();
  }

  /** Baris pratinjau untuk satu target (cocok persis pada sel target). */
  previewRow(target: string): Locator {
    return this.preview.locator('table tbody tr', {
      has: this.page.getByText(target, { exact: true }),
    });
  }
}
