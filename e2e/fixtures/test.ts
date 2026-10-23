import { test as base, expect, type Page } from '@playwright/test';

// Host yang boleh dihubungi browser selama E2E. Apa pun di luar ini = kegagalan
// pengaman, bukan sekadar diblok diam-diam.
const LOCAL_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

/**
 * Fixture `test` yang dipakai semua spec. Selain fixture Playwright standar, ia
 * memasang pengaman egress di tingkat browser: setiap request ke host non-lokal
 * di-abort. Digabung dengan engine mock (server tak pernah egress) dan env proxy
 * mati di webServer, ini menutup semua jalur keluar — sesuai garis merah persona
 * BH-P05 (E2E tidak boleh menyentuh aset eksternal nyata).
 */
export const test = base.extend<{ blockExternalEgress: void }>({
  blockExternalEgress: [
    async ({ page }: { page: Page }, use: (r: void) => Promise<void>) => {
      // Hanya INTERSEP url non-lokal. Request lokal sengaja tidak dirutekan sama
      // sekali agar konteks navigasi (dan cookie SameSite=Strict) tak berubah —
      // intercept+continue pada navigasi top-level membuat Chromium menjatuhkan
      // cookie Strict dan merusak CSRF form. Yang eksternal di-abort keras.
      await page.route(
        (url) => !LOCAL_HOSTS.has(url.hostname),
        (route) => {
          console.error(`[egress-guard] memblok request non-lokal: ${route.request().url()}`);
          return route.abort('blockedbyclient');
        },
      );
      await use(undefined);
    },
    { auto: true },
  ],
});

export { expect };
