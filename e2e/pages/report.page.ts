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

  /**
   * Kontrol yang benar-benar MENGIRIM/submit — harus NOL. Catatan: tombol
   * "Export HackerOne/Bugcrowd" adalah UNDUH (format untuk submit manual),
   * bukan kontrol submit, jadi nama platform saja tak dihitung di sini.
   */
  submitLikeControls(): Locator {
    const re = /submit|kirim|send|lapor/i;
    return this.page.getByRole('button', { name: re }).or(this.page.getByRole('link', { name: re }));
  }
}
