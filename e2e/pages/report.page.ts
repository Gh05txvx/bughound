import { type Page, type Locator } from '@playwright/test';

/** Layar Report: draft dari temuan terkonfirmasi. Tanpa auto-submit. */
export class ReportPage {
  constructor(private readonly page: Page) {}

  async goto(program: string) {
    await this.page.goto(`/report?program=${encodeURIComponent(program)}`);
  }

  downloadMd(): Locator {
    return this.page.getByRole('link', { name: 'Unduh .md' });
  }

  printPdf(): Locator {
    return this.page.getByRole('link', { name: /Cetak/ });
  }

  /** Setiap kontrol yang terlihat seperti "kirim/submit" — harus NOL. */
  submitLikeControls(): Locator {
    return this.page.getByRole('button', { name: /submit|kirim|send|lapor/i })
      .or(this.page.getByRole('link', { name: /submit|kirim(?!an manual)|send|hackerone|bugcrowd/i }));
  }
}
