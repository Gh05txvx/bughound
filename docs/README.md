# Dokumen BugHound

Berkas Markdown di folder ini adalah **spesifikasi teknis fondasi** dan **panduan operasional** BugHound, disusun agar bisa dibaca langsung di dalam repo. Sebagian merupakan hasil ekspor dari Claude Docs; `guides/` ditulis langsung di repo.

> Catatan: dokumen perencanaan & proses internal (PRD, design spec, persona kerja, audit pre-launch, ADR) dikelola privat oleh pemilik repo dan **tidak disertakan di repo publik**.

## Struktur

```
docs/
  specs/            — spesifikasi teknis fondasi (dirujuk semua komponen)
  guides/           — panduan operasional fitur (ditulis langsung di repo)
  BH-CHANGELOG.md   — catatan perkembangan implementasi (apa yang sudah dibangun)
```

> **Perkembangan implementasi:** lihat [`BH-CHANGELOG.md`](BH-CHANGELOG.md) untuk ringkasan apa saja yang sudah dibangun (M0–M3, rilis, keamanan, engine, dll).

## Daftar berkas

### `docs/specs/` — Spesifikasi teknis (fondasi)

| ID | Berkas |
| --- | --- |
| `BH-SPEC-FINDING` | `specs/BH-SPEC-FINDING-skema-temuan.md` |
| `BH-SPEC-SCOPE` | `specs/BH-SPEC-SCOPE-scope-guard.md` |
| `BH-SPEC-PAYLOAD` | `specs/BH-SPEC-PAYLOAD-bank-payload.md` |

### `docs/guides/` — Panduan operasional

| ID | Berkas | Inti |
| --- | --- | --- |
| `BH-GUIDE-PROXY` | `guides/BH-GUIDE-PROXY.md` | Menu Proxy: rantai upstream, endpoint echo IP (wajib in-scope), proxy yang bisa dipakai, requirement untuk program bug bounty eksternal. |

## Catatan ekspor

- **Diagram tidak terbawa.** Hanya teks, tabel, dan blok kode yang ikut ke Markdown. Setiap diagram yang hilang ditandai dengan baris `> _Diagram: … — tersedia di versi Claude Docs_` di posisi aslinya.
- **Chip tanggal/mention** dipertahankan sebagai teks biasa (mis. `Oct 21, 2026 · @Gh05t`).
- Berkas ini adalah salinan statis. Bila dokumen sumber di Claude Docs diperbarui, ekspor ulang untuk menyinkronkan.
