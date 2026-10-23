import { type Page, type Locator, expect } from '@playwright/test';

/** Layar Scan: konfigurasi scope + target, jalankan scan (engine mock). */
export class ScanPage {
  readonly result: Locator;
  constructor(private readonly page: Page) {
    this.result = page.locator('#result');
  }

  async goto(program?: string) {
    await this.page.goto(program ? `/scan?program=${encodeURIComponent(program)}` : '/scan');
  }

  async fill(opts: {
    program: string;
    inScope: string;
    outScope?: string;
    targets: string;
    seeds?: string;
    rps?: string;
  }) {
    await this.page.locator('input[name="program"]').fill(opts.program);
    await this.page.locator('textarea[name="seeds"]').fill(opts.seeds ?? '');
    await this.page.locator('textarea[name="in_scope"]').fill(opts.inScope);
    await this.page.locator('textarea[name="out_scope"]').fill(opts.outScope ?? '');
    await this.page.locator('textarea[name="targets"]').fill(opts.targets);
    if (opts.rps) await this.page.locator('input[name="rps"]').fill(opts.rps);
  }

  /** Klik "Jalankan scan"; otomatis menerima dialog konfirmasi (hx-confirm). */
  async run() {
    this.page.once('dialog', (d) => d.accept());
    await this.page.getByRole('button', { name: 'Jalankan scan' }).click();
  }

  /** Menunggu run selesai: link "Lihat findings" muncul di keadaan terminal. */
  async waitForDone() {
    await expect(this.result.getByRole('link', { name: /Lihat findings/ })).toBeVisible({ timeout: 20_000 });
  }

  async openFindings() {
    await this.result.getByRole('link', { name: /Lihat findings/ }).click();
  }

  savedChip(): Locator {
    return this.result.getByText(/temuan baru/);
  }

  deniedHeading(): Locator {
    return this.result.getByRole('heading', { name: /Ditolak scope guard/ });
  }
}
