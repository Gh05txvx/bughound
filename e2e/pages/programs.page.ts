import { type Page, type Locator } from '@playwright/test';

/** Daftar program (definisi scope tersimpan). */
export class ProgramsPage {
  constructor(private readonly page: Page) {}

  async goto() {
    await this.page.goto('/programs');
  }

  async newProgram() {
    await this.page.getByRole('link', { name: '+ Program baru' }).click();
  }

  row(name: string): Locator {
    return this.page.getByRole('row', { name: new RegExp(name) });
  }
}
