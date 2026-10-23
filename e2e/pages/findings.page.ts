import { type Page, type Locator } from '@playwright/test';

type BulkAction = 'Konfirmasi' | 'False positive' | 'Abaikan';

/** Layar Findings: daftar temuan, filter, aksi massal, detail/triase. */
export class FindingsPage {
  constructor(private readonly page: Page) {}

  async goto(program: string) {
    await this.page.goto(`/findings?program=${encodeURIComponent(program)}`);
  }

  rows(): Locator {
    return this.page.locator('table.findings tbody tr.row');
  }

  async filter(opts: { severity?: string; status?: string; type?: string; run?: string }) {
    const form = this.page.locator('form.filters');
    if (opts.severity !== undefined) await form.locator('select[name="severity"]').selectOption(opts.severity);
    if (opts.status !== undefined) await form.locator('select[name="status"]').selectOption(opts.status);
    if (opts.type !== undefined) await form.locator('input[name="type"]').fill(opts.type);
    if (opts.run !== undefined) await form.locator('input[name="run"]').fill(opts.run);
    await form.getByRole('button', { name: 'Filter' }).click();
  }

  /** Centang semua checkbox baris yang sedang tampil. */
  async selectAllVisible() {
    const boxes = this.page.locator('#bulkform input[name="ids"]');
    const n = await boxes.count();
    for (let i = 0; i < n; i++) await boxes.nth(i).check();
  }

  async bulk(action: BulkAction) {
    await this.page.locator('.bulk-bar').getByRole('button', { name: action }).click();
  }

  /** Buka detail satu temuan dengan mengklik judulnya (bubbling ke baris → hx-get). */
  async open(titleText: string) {
    await this.page.getByText(titleText).click();
  }

  detail(): Locator {
    return this.page.locator('#detail');
  }
}
