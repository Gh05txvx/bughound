# E2E (Playwright) — bughound

Pengujian end-to-end alur pengguna lewat browser (persona **BH-P05-E2E**).

> **Garis merah keamanan.** E2E **tidak pernah** memicu scan nyata atau menyentuh
> aset eksternal. Dijamin berlapis:
> 1. Server dijalankan dengan **engine mock** (`-engine mock`) — tak ada koneksi keluar.
> 2. Store **in-memory ephemeral** (`-db ""`) — tak ada file/secret tertinggal.
> 3. Bind **localhost** saja.
> 4. **Egress diblok** di dua tempat: env proxy mati pada proses server, dan
>    pengaman di browser (`fixtures/test.ts`) meng-abort request non-lokal.
> Target yang dipakai hanya domain dummy (`demo.test`, `acme.test`; spec impor
> memakai `example.com` karena importer menolak TLD tak dikenal).

## Jalankan

Butuh Go di PATH + Node 18+.

```bash
cd e2e
npm install                 # sekali
npx playwright install chromium   # sekali (unduh browser)
npm test                    # jalankan semua skenario
npm run test:headed         # dengan browser terlihat
npm run report              # buka laporan HTML terakhir
```

`webServer` di `playwright.config.ts` membangun binary `bughound-e2e` dari
`./cmd/bughound` lalu menjalankannya (port `8799`). Tak perlu start server manual.

## Struktur

```
tests/    skenario per alur (2 teratas = kritis, selalu dijalankan)
  scope-guard.spec.ts       KRITIS: tolak target luar scope (pratinjau)
  no-auto-submit.spec.ts    KRITIS: report draft, tanpa auto-submit
  scan-flow.spec.ts         happy-path scan (engine mock)
  triage.spec.ts            filter severity + konfirmasi massal
  program-scope.spec.ts     buat program + scope, prefill scan
  program-import.spec.ts    impor scope platform: tinjau dulu, tahan eksklusi tak terwakili
pages/    page object per layar (selector berbasis peran/teks)
fixtures/ fixture test + pengaman egress browser
utils/    helper seed (scan mock, konfirmasi)
```

## Catatan

- Selector berbasis **peran/teks** dan atribut `name` form yang stabil; tanpa XPath/indeks rapuh.
- **Auto-wait** Playwright, tanpa `sleep` tetap.
- Isolasi: tiap test memakai **nama program unik** sehingga tak saling bergantung.
- Kredensial tidak pernah ditulis di test; happy-path berjalan tanpa auth (localhost).
