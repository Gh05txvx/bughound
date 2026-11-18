import { test as base, expect, type Page } from '@playwright/test';

// Hosts the browser may contact during E2E. Anything outside this set = a guard
// failure, not just a quiet block.
const LOCAL_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

/**
 * Fixture `test` used by every spec. On top of the standard Playwright fixture,
 * it installs an egress guard at the browser level: every request to a non-local
 * host is aborted. Together with the mock engines (the server never egresses) and
 * the dead proxy env in webServer, this closes every outbound path, matching the
 * BH-P05 persona red line (E2E must never touch real external assets).
 */
export const test = base.extend<{ blockExternalEgress: void }>({
  blockExternalEgress: [
    async ({ page }: { page: Page }, use: (r: void) => Promise<void>) => {
      // Only INTERCEPT non-local urls. Local requests are deliberately not routed at
      // all so the navigation context (and SameSite=Strict cookies) stays intact:
      // intercept+continue on a top-level navigation makes Chromium drop the Strict
      // cookie and breaks the CSRF form. External ones are hard-aborted.
      await page.route(
        (url) => !LOCAL_HOSTS.has(url.hostname),
        (route) => {
          console.error(`[egress-guard] blocking non-local request: ${route.request().url()}`);
          return route.abort('blockedbyclient');
        },
      );
      await use(undefined);
    },
    { auto: true },
  ],
});

export { expect };
