# Dokumen bughound

Berkas Markdown di folder ini adalah hasil ekspor dari Claude Docs, disusun agar bisa dibaca langsung di dalam repo (termasuk oleh Claude Code di VS Code). Titik masuk utama tetap `CLAUDE.md` di root repo.

## Struktur

```
docs/
  specs/      — spesifikasi teknis fondasi (dirujuk semua komponen)
  product/    — PRD produk & design spec
  personas/   — 8 mode kerja (persona) yang bisa diminta pengguna
```

## Daftar berkas

### `docs/specs/` — Spesifikasi teknis (fondasi)

| ID | Berkas |
| --- | --- |
| `BH-SPEC-FINDING` | `specs/BH-SPEC-FINDING-skema-temuan.md` |
| `BH-SPEC-SCOPE` | `specs/BH-SPEC-SCOPE-scope-guard.md` |
| `BH-SPEC-PAYLOAD` | `specs/BH-SPEC-PAYLOAD-bank-payload.md` |

### `docs/product/` — Produk & desain

| ID | Berkas |
| --- | --- |
| `BH-DOC-PRD` (= `BH-P01-PRD`) | `product/BH-DOC-PRD.md` |
| `BH-P02-DESIGN` | `product/BH-P02-DESIGN.md` |

### `docs/personas/` — Persona

| ID | Berkas |
| --- | --- |
| `BH-P03-APPSEC` | `personas/BH-P03-APPSEC-roe-audit.md` |
| `BH-P04-DEBUG` | `personas/BH-P04-DEBUG.md` |
| `BH-P05-E2E` | `personas/BH-P05-E2E.md` |
| `BH-P06-CLEANUP` | `personas/BH-P06-CLEANUP.md` |
| `BH-P07-COMMIT` | `personas/BH-P07-COMMIT.md` |
| `BH-P08-ARCH` | `personas/BH-P08-ARCH.md` |

## Catatan ekspor

- **Diagram tidak terbawa.** Hanya teks, tabel, dan blok kode yang ikut ke Markdown. Setiap diagram yang hilang ditandai dengan baris `> _Diagram: … — tersedia di versi Claude Docs_` di posisi aslinya.
- **Chip tanggal/mention** dipertahankan sebagai teks biasa (mis. `Oct 21, 2026 · @Gh05t`).
- Berkas ini adalah salinan statis. Bila dokumen sumber di Claude Docs diperbarui, ekspor ulang untuk menyinkronkan.

## Sumber online (Claude Docs)

Versi lengkap dengan diagram ada di Claude Docs (butuh login akun pemilik):

| ID | URL |
| --- | --- |
| `BH-DOC-PRD` | https://claude.ai/code/artifact/85c9efcf-a6b7-4621-9293-bbd40471d677 |
| `BH-P02-DESIGN` | https://claude.ai/code/artifact/93062ca6-e94f-4082-bd5b-60a9d89368b5 |
| `BH-P03-APPSEC` | https://claude.ai/code/artifact/b1a48a13-6acb-44ef-9cd9-7c149173c713 |
| `BH-P04-DEBUG` | https://claude.ai/code/artifact/2d9df6d1-821a-4f80-9724-90d303706b69 |
| `BH-P05-E2E` | https://claude.ai/code/artifact/e012c950-d78c-4444-bac2-5f3755418f93 |
| `BH-P06-CLEANUP` | https://claude.ai/code/artifact/f893fe88-a264-4f9a-8210-97d60fd50e13 |
| `BH-P07-COMMIT` | https://claude.ai/code/artifact/714f80bf-dae0-48c9-9867-fdb69197c08f |
| `BH-P08-ARCH` | https://claude.ai/code/artifact/55c65a9e-29b5-44d7-9995-846ad138093d |
| `BH-SPEC-FINDING` | https://claude.ai/code/artifact/ce078458-98e1-4746-a409-2b8038647ca5 |
| `BH-SPEC-SCOPE` | https://claude.ai/code/artifact/ec1c45cf-90cc-4199-9a8e-d45ae5ec810f |
| `BH-SPEC-PAYLOAD` | https://claude.ai/code/artifact/2fa0711a-a5b1-4fe6-82ee-681eaaee63c5 |
