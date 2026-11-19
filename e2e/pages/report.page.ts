import { type Page, type Locator } from '@playwright/test';

/** Report screen: a draft from confirmed findings. No auto-submit. */
export class ReportPage {
  constructor(private readonly page: Page) {}

  async goto(program: string) {
    await this.page.goto(`/report?program=${encodeURIComponent(program)}`);
  }

  downloadMd(): Locator {
    return this.page.getByRole('link', { name: 'Download .md' });
  }

  printPdf(): Locator {
    return this.page.getByRole('link', { name: /Print/ });
  }

  /** Platform export buttons in the report header (DOWNLOAD .md for manual submit). */
  exportLink(platform: 'HackerOne' | 'Bugcrowd'): Locator {
    return this.page.getByRole('link', { name: `Export ${platform}` });
  }

  /**
   * Controls that actually SEND/submit, which must be ZERO. The
   * "Export HackerOne/Bugcrowd" buttons only DOWNLOAD a format for manual
   * submission, so a platform name on its own does not count here.
   * Scoped to <main>: the sidebar "Reports" nav link is chrome, not a report
   * action, and would otherwise match /report/ now that the UI is English.
   */
  submitLikeControls(): Locator {
    const re = /submit|send|report/i;
    const main = this.page.getByRole('main');
    return main.getByRole('button', { name: re }).or(main.getByRole('link', { name: re }));
  }
}
