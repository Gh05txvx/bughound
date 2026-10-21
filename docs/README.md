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

## Sumber diagram

Berkas Markdown di repo ini adalah salinan statis dan menjadi sumber kebenaran. Diagram tidak ikut terekspor dan ditandai dengan baris `> _Diagram: … — tersedia di versi Claude Docs_` pada posisi aslinya. Versi sumber berdiagram disimpan privat oleh pemilik repo.
