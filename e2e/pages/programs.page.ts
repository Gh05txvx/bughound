import { type Page, type Locator } from '@playwright/test';

/** Program list (the stored scope definitions). */
export class ProgramsPage {
  constructor(private readonly page: Page) {}

  async goto() {
    await this.page.goto('/programs');
  }

  async newProgram() {
    await this.page.getByRole('link', { name: '+ New program' }).click();
  }

  row(name: string): Locator {
    return this.page.getByRole('row', { name: new RegExp(name) });
  }
}
