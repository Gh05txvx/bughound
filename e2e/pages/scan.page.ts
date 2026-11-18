import { type Page, type Locator, expect } from '@playwright/test';

/** Scan screen: configure scope + targets, run the scan (mock engines). */
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

  /** Click "Run scan"; auto-accept the confirm dialog (hx-confirm). */
  async run() {
    this.page.once('dialog', (d) => d.accept());
    await this.page.getByRole('button', { name: 'Run scan' }).click();
  }

  /** Wait for the run to finish: the "View findings" link shows in a terminal state. */
  async waitForDone() {
    await expect(this.result.getByRole('link', { name: /View findings/ })).toBeVisible({ timeout: 20_000 });
  }

  async openFindings() {
    await this.result.getByRole('link', { name: /View findings/ }).click();
  }

  savedChip(): Locator {
    return this.result.getByText(/new findings/);
  }

  deniedHeading(): Locator {
    return this.result.getByRole('heading', { name: /Denied by the scope guard/ });
  }
}
