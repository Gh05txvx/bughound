# Template deteksi custom BugHound (Bank Payload)

Direktori ini berisi template nuclei **bikinan sendiri** yang dijalankan runner
`nuclei-custom` (lihat `BH-SPEC-PAYLOAD` dan `cmd/bughound` roster). Runner ini
memanggil `nuclei -t <dir ini>` sehingga **hanya** template di sini yang jalan,
terpisah dari runner `nuclei` resmi yang memakai set bawaan penuh.

## Aturan (mengikat)

1. **Read-only saja.** Template di sini wajib non-destruktif: deteksi lewat
   request baca (GET, atau query baca seperti introspection GraphQL). Dilarang
   menulis/mengubah/menghapus keadaan target, mengunggah berkas, atau memicu
   DoS. Tag `dos`/`smuggling` dan ID unsafe tetap diblok struktural oleh
   `nonDestructiveArgs()`, tapi jangan bergantung padanya — tulis template yang
   memang aman.
2. **Jangan seret rahasia ke evidence.** Cocokkan penanda struktural (pola kunci,
   nama field), bukan menyedot nilai sensitif.
3. **Satu temuan = satu kelas jelas.** Sertakan `classification.cwe-id` dan
   `tags` agar normalisasi → OWASP + remediasi actionable bekerja di draft report.

## Aktivasi

Runner opt-in: tambahkan `nuclei-custom` ke daftar `-engine` **dan** arahkan dir:

```
-engine nuclei,ffuf,zap,nuclei-dast,dalfox,nuclei-custom \
-custom-templates ./templates/custom      # atau env BUGHOUND_CUSTOM_TEMPLATES
```

Di image, dir ini di-COPY ke `/app/templates/custom` dan env
`BUGHOUND_CUSTOM_TEMPLATES` menunjuk ke sana.
