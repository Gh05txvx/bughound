# BH-DESIGN-analyst-spk — App Analyst + SPK (Decision Support) untuk triase temuan BugHound

> Dokumen desain **lokal** (gitignored). Merancang app TERPISAH dari core BugHound yang:
> membaca temuan via API baca-saja → analitik deterministik → peringkat SAW → output "what-if"
> (rencana validasi manual di Burp). AI = penasihat; **manusia yang mengeksekusi di Burp**.
> Terakhir diperbarui: 2026-11-13.

---

## 1. Prinsip & batas

- **Baca-saja.** App hanya `GET /api/v1/findings` (Basic, read-only). Tak pernah memicu scan, submit, atau menyentuh target. Tak ada jalur samping ke scanner (Prinsip #1 BugHound tetap utuh).
- **Di luar core.** BugHound = sumber kebenaran; app ini konsumen. Kalau app rusak, core tak terdampak.
- **AI = generator hipotesis & narasi, bukan pelaku.** Angka (SAW, klaster, FP) dari **kode deterministik**. LLM hanya menarasikan `why` + menyusun `hypotheses`. Eksekusi di Burp = **manusia**.
- **Data-handling:** `evidence` discrub sebelum menyentuh LLM (lihat §6).

## 2. Alur

```
BugHound  ──GET /api/v1/findings?program=X──▶  Analyst+SPK
(sumber)      (Basic auth, JSON read-only)       │
                                                 ├─ ingest  → model.Finding
                                                 ├─ analyst → klaster, fp_likelihood, derived
                                                 ├─ saw     → skor + ranking (explainable)
                                                 └─ whatif  → scaffold rencana + evidence terscrub
                                                                  │
                                                        kamu + Burp Repeater (eksekusi manual)
```

Antarmuka ke AI (Claude): **MCP server** membungkus app → tool `list_findings`, `rank_findings`, `whatif`. Claude memanggilnya, menalar, menyusun hipotesis atas evidence terscrub.

## 3. Model data

### 3.1 Di-ingest dari API (field skema `finding.Finding`)

| Field | Tipe | Dipakai |
|---|---|---|
| `id`, `dedup_key`, `program`, `run_id`, `target` | string | identitas, klaster |
| `type`, `title`, `description` | string | tampilan, heuristik |
| `severity` | enum `info\|low\|medium\|high\|critical` | C2 |
| `confidence` | enum `low\|medium\|high` | C1 |
| `cwe[]`, `tags[]` | []string | heuristik |
| `owasp` | obj (kategori OWASP 2021) | C6 |
| `source_engine`, `source_template` | string | C1 exploitability, FP |
| `location{url,method,parameter,param_location}` | obj | target what-if |
| `evidence{request,response_excerpt,payload,matched,screenshot_ref}` | obj | what-if (base request) |
| `reproduction[]`, `impact` | - | konteks narasi |
| `status` | enum `new\|confirmed\|duplicate\|false_positive\|ignored` | filter |
| `duplicate_of`, `in_report` | - | filter |
| `created_at`, `updated_at` | time | C8 freshness |

### 3.2 Enrichment eksternal (opsional)

- **Scope asset** (dari import CSV HackerOne/Bugcrowd): `asset.max_severity`, `eligible_for_bounty` → C3 bounty. Fallback = `severity` kalau scope tak tersedia.

### 3.3 Dihitung (layer analyst — deterministik)

| Derived | Rumus |
|---|---|
| `cluster_id`, `cluster_size` | group by `dedup_key` → fallback `host(url)+type+parameter` |
| `siblings_on_endpoint` | jumlah temuan lain ber-`location.url` sama → potensi chain |
| `exploitability_raw` | `confidence_num × engine_factor` (§4, C1) |
| `fp_likelihood` ∈ [0,1] | heuristik (§3.4) |
| `bounty_weight` ∈ [1,5] | `asset.max_severity` × (eligible_for_bounty? 1 : 0.4); fallback `severity_num` |

### 3.4 Heuristik `fp_likelihood` (tunable)

| Kondisi | fp |
|---|---|
| `status=confirmed` | 0.0 |
| `confidence=high` & engine ∈ {nuclei-dast, dalfox} | 0.1 |
| engine=ffuf & respons mirip SPA/soft-404 (heuristik body) | 0.7 |
| engine pasif {retire, zap-pasif} & `confidence=low` | 0.5 |
| default | 0.3 |

## 4. SPK — SAW (Simple Additive Weighting)

**Algoritma:** matriks keputusan (alternatif = temuan, kolom = kriteria) → normalisasi → jumlah berbobot → ranking desc.

- Benefit: `r_ij = x_ij / max_i(x_ij)`
- Cost:    `r_ij = min_i(x_ij) / x_ij`
- Skor:    `V_i = Σ_j w_j · r_ij`,  dengan `Σ w_j = 1`

### 4.1 Kriteria final (default — tunable)

| # | Kriteria | Tipe | Nilai mentah | Bobot |
|---|---|---|---|---|
| C1 | Exploitability | benefit | `confidence_num(1/2/3) × engine_factor` | **0.26** |
| C2 | Signal payout | benefit | kelas kerentanan (§4.2): high 1.0 · netral 0.5 · noise 0.1 | **0.22** |
| C3 | Potensi bounty | benefit | `bounty_weight` 1–5 (scope `max_severity` bila ada) | **0.16** |
| C4 | Severity/Impact | benefit | info1·low2·med3·high4·crit5 (bobot sengaja rendah: severity scanner sering menggelembung utk passive) | **0.12** |
| C5 | FP-likelihood | cost | `fp_likelihood` 0–1 | **0.12** |
| C6 | Effort verifikasi | cost | reflected 1 · SQLi/IDOR 2 · blind/2nd-order 3 | **0.06** |
| C7 | OWASP priority | benefit | mapping kategori (§4.4) | **0.04** |
| C8 | Freshness | benefit | relatif ke `created_at` terbaru di batch: gap-hari ≤1→5 · ≤7→4 · ≤30→3 · else 2 | **0.02** |

Σ bobot = **1.00**. Bobot disimpan di config (`weights.yaml`) → mudah di-tune tanpa ubah kode.

### 4.2 Signal payout (C2) — lever anti "header-noise"

Masalah nyata (terbukti di data RF live): tanpa C2, hygiene pasif (CSP/SRI/clickjacking/HSTS/cookie/timestamp) yang di-rate "medium" oleh scanner naik ke puncak, padahal di bug bounty **nyaris won't-pay**. C2 memberi sinyal payout per **kelas kerentanan** (bukan severity scanner):

- **high 1.0** — eksploitatif/berbayar: sqli, xss, rce, ssrf, xxe, idor/bola, broken-access, path/dir-traversal, lfi/rfi, deserial, ssti, exposed-panel/config, secret/key-leak, takeover, file-upload.
- **noise 0.1** — hygiene/header: csp, sub-resource-integrity, clickjacking, hsts, samesite/cookie-flags, referrer/permissions-policy, x-content-type, x-powered-by, timestamp-disclosure, cache-control, mixed-content, cross-domain-javascript, tls/ssl best-practice.
- **netral 0.5** — selain itu (mis. `exposed-path` ffuf — perlu dilihat, belum tentu bug).

Pencocokan pada **batas token** (lookaround, bukan substring telanjang) agar token pendek tak nyangkut (mis. `rce` di `resource`, `file-inclusion` di `cross-domain-javascript-source-file-inclusion`), dan **noise dicek dulu** (mis. `x-xss-protection` tak ter-high via token `xss`). Pola ada di `signal_patterns` (`weights.yaml`) → tunable.

**Signal juga membaca URL path** (hanya **mempromosikan** ke high, tak pernah menurunkan ke noise): `exposed-path` generik ke `/.git`, `/.env`, `/admin`, `/backup`, `/actuator`, `wp-admin` → high 1.0. Sebaliknya path **membosankan** (file standar: `robots.txt`, `sitemap`, `/.well-known`, `favicon`, `healthz`, `manifest.json`) menurunkan `exposed-path` NETRAL ke noise, agar endpoint nyata (`/search`, `/signup`) naik di atas file statis. Daftar di `signal_patterns.boring`.

### 4.2a FP ffuf — kalibrasi soft-404/SPA (C5)

`exposed-path` dari ffuf rawan palsu di app yang membalas 200 untuk hampir semua path. Dua prior (tunable di `heuristics`) menaikkan `fp_likelihood`: (1) **penanda shell SPA** (React/Vue/Angular/Next/Nuxt/Svelte/webpack) di body → fp 0.7; (2) **flood** — bila satu host punya ≥`ffuf_flood_threshold` (default 8) temuan `exposed-path`, itu indikasi soft-404/wildcard → fp dipaksa ≥`ffuf_flood_fp` (0.6). Temuan `confirmed` tak pernah dinaikkan.

### 4.3 `engine_factor`

`nuclei-dast`=1.0 · `dalfox`=1.0 · `nuclei`=0.8 · `zap`(aktif)=0.8 · `ffuf`=0.7 · `retire`/`zap-pasif`/`sast`=0.5 · default 0.6.

### 4.4 OWASP priority (C7, nilai 1–5)

A01 Broken Access Control = 5 · A03 Injection = 5 · A10 SSRF = 4 · A07 Auth Failures = 4 · A02 Crypto Failures = 4 · A04 Insecure Design = 3 · A05 Misconfig = 3 · A06 Vulnerable Components = 3 · A08 Integrity = 3 · A09 Logging = 2 · (tak terklasifikasi) = 2.

### 4.5 Pra-filter (sebelum SAW)

Buang: `status ∈ {duplicate, false_positive, ignored}`; default `info` severity opsional di-skip; hanya satu wakil per `cluster_id` (yang skor tertinggi) agar tak dobel verifikasi.

### 4.6 Contoh

Kolom = C1 exploitability · C2 signal · C3 bounty · C4 severity · C5 fp · C6 effort · C7 owasp · C8 freshness.

| Temuan | C1 | C2 | C3 | C4 | C5 | C6 | C7 | C8 |
|---|---|---|---|---|---|---|---|---|
| SQLi `/rest/search` (nuclei-dast, high) | 3.0 | 1.0 | 5 | 5 | 0.1 | 2 | 5 | 5 |
| XSS refl `/q` (dalfox, med) | 2.0 | 1.0 | 4 | 3 | 0.2 | 1 | 5 | 5 |
| `exposed-path /admin` (ffuf, low) | 2.1 | 0.5 | 2 | 2 | 0.3 | 2 | 3 | 5 |
| Missing-CSP header (zap, med) | 2.4 | 0.1 | 3 | 3 | 0.3 | 2 | 3 | 5 |

→ ranking SQLi > XSS > exposed-path > **Missing-CSP** — hygiene header turun ke dasar meski severity "medium"-nya ≥ exposed-path, karena C2 noise (0.1) menenggelamkannya. **Terbukti pada data RF nyata**: top bergeser dari header-hygiene (skor 0.976) ke `exposed-path` (0.858), header turun. **Breakdown selalu ditampilkan** (explainable).

## 5. Output "what-if" (per temuan teratas)

Schema stabil (JSON) + render markdown. Bagian deterministik dari app; `hypotheses` + `why` diisi LLM atas evidence terscrub.

```json
{
  "finding_id": "…", "rank": 1, "score": 0.95,
  "score_breakdown": {"C1":0.26,"C2":0.22,"C3":0.16,"C4":0.12,"C5":0.12,"C6":0.06,"C7":0.04,"C8":0.02},
  "why": "<LLM: ringkas kenapa prioritas>",
  "base_request_ref": "evidence.request (sudah di Repeater)",
  "target": {"url":"…/rest/search","method":"GET","parameter":"q"},
  "hypotheses": [
    {"mutation":"q=' OR 1=1--","expected":"baris bertambah / error hilang","confirms":"boolean SQLi"},
    {"mutation":"q=1;WAITFOR DELAY '0:0:5'--","expected":"respons ~5s","confirms":"time-based blind"}
  ],
  "decision": "verify_now | likely_fp | needs_more_info",
  "safety": "non-destruktif (SELECT/boolean/time); hormati rate-limit & RoE program"
}
```

## 6. Data-handling (wajib)

Sebelum evidence menyentuh LLM (untuk `hypotheses`/`why`):
- **Scrub** `Authorization`, `Cookie`, `Set-Cookie`, token/bearer, dan PII di `response_excerpt` → placeholder `[REDACTED]`.
- Kirim **minimal**: `url`, `method`, `parameter`, `payload`, `matched`, potongan request terscrub — bukan dump penuh.
- Program sensitif (finansial, mis. Deriv) → pertimbangkan **model lokal**.
- SAW/klaster/FP **tak** butuh LLM → tak ada data yang keluar untuk bagian itu.

## 7. Struktur app (lihat `../bughound-analyst/`)

```
bughound-analyst/
├─ bughound_analyst/
│  ├─ __init__.py
│  ├─ config.py        # bobot, engine_factor, OWASP map, effort map (tunable)
│  ├─ client.py        # BughoundClient: GET /api/v1/findings (Basic, read-only)
│  ├─ model.py         # Finding dataclass dari JSON skema
│  ├─ analyst.py       # klaster, fp_likelihood, derived metrics
│  ├─ saw.py           # SAW: normalisasi + skor + ranking (REAL + diuji)
│  ├─ scrub.py         # redaksi evidence sebelum LLM
│  └─ whatif.py        # scaffold rencana what-if (deterministik; hypotheses diisi LLM)
├─ server.py           # MCP server: tool list_findings / rank_findings / whatif
├─ tests/test_saw.py   # unit test SAW (ranking contoh §4.5)
├─ weights.yaml        # bobot & mapping (sumber tunable utk config.py)
├─ requirements.txt    # httpx, pyyaml, mcp
├─ .env.example        # BUGHOUND_URL, BUGHOUND_USER, BUGHOUND_PASS
└─ README.md
```

## 8. Backlog

- [ ] Enrichment scope asset (max_severity/bounty) dari import CSV.
- [ ] Heuristik FP SPA (deteksi soft-404/body SPA) — kalibrasi dengan data lab.
- [ ] Opsi model lokal untuk `whatif` program sensitif.
- [ ] (opsional) tool tulis terbatas `set_triage_status` via API — hanya bila BugHound menambah endpoint tulis ber-RBAC + audit (belum ada).
