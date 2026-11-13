# bughound-analyst

Triase + **SPK (SAW)** + **what-if** atas temuan BugHound. App **terpisah** dari core
BugHound. **Baca-saja** (hanya `GET /api/v1/findings`) — tak pernah memicu scan/submit.
AI = penasihat; **eksekusi validasi di Burp = manusia**.

> Desain lengkap: [`docs/BH-DESIGN-analyst-spk.md`](docs/BH-DESIGN-analyst-spk.md).

## Alur

```
BugHound ─GET /api/v1/findings─▶ ingest → analyst(klaster,FP,derived) → SAW(ranking) → what-if(scaffold)
(read-only)                                                                                   │
                                                                              kamu + Burp Repeater (manual)
```

## Pasang

```bash
python -m venv .venv && . .venv/Scripts/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env    # isi BUGHOUND_URL/USER/PASS (akun viewer cukup)
```

## Pakai

**Uji (tanpa jaringan):**
```bash
python tests/test_saw.py        # atau: pytest
```

**Sebagai MCP server (untuk Claude):**
```bash
python server.py                # tool: rank(program, top), whatif(program, finding_id)
```
> Butuh MCP SDK. `mcp>=2` me-rename `FastMCP`→`MCPServer`; `server.py` mendukung
> keduanya (2.x diutamakan, fallback 1.x). Kredensial dibaca dari `.env` **di
> samping `server.py`** (jadi terbaca walau klien memanggil dari cwd lain).

Registrasi ke klien MCP sebagai server `bughound-analyst` (ganti path sesuai mesinmu):

```jsonc
{
  "mcpServers": {
    "bughound-analyst": {
      "command": "<path>/.venv/Scripts/python.exe",
      "args": ["<path>/server.py"]
    }
  }
}
```
- **Claude Desktop**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Claude Code (user scope)**: `claude mcp add bughound-analyst -- "<path>/.venv/Scripts/python.exe" "<path>/server.py"`

Claude memanggil `rank` → dapat peringkat SAW; `whatif` → scaffold + evidence terscrub,
lalu Claude menyusun `hypotheses`/`why`. **Kamu** yang menjalankan di Burp.

## Komponen

| Modul | Isi |
|---|---|
| `bughound_analyst/client.py` | klien API baca-saja (Basic) |
| `bughound_analyst/model.py` | `Finding` dari JSON skema BugHound |
| `bughound_analyst/analyst.py` | klaster, fp_likelihood, derived, prefilter (deterministik) |
| `bughound_analyst/saw.py` | **SAW**: normalisasi + skor + ranking (explainable) |
| `bughound_analyst/scrub.py` | redaksi evidence sebelum LLM |
| `bughound_analyst/whatif.py` | scaffold rencana (hypotheses diisi LLM) |
| `bughound_analyst/config.py` + `weights.yaml` | bobot & mapping — **tunable** |
| `server.py` | MCP server |

## Aman secara desain

- **Baca-saja**: tak ada tool yang mengubah state / menyentuh target.
- **Angka dari kode**, bukan LLM (SAW/klaster/FP deterministik & diuji).
- **Evidence discrub** sebelum ke LLM (`scrub.py`) — kredensial/PII → `[REDACTED]`.
- What-if = **saran**; tak pernah auto-eksekusi. Burp dijalankan manusia, dalam RoE.

## Tuning SPK

Edit `weights.yaml` (Σ weights = 1.0, divalidasi saat load). 8 kriteria: exploitability,
**signal** (payout per kelas — anti header-noise), bounty, severity, fp_likelihood (cost),
effort (cost), owasp, freshness. Pola klasifikasi signal (high/noise) juga di `weights.yaml`
(`signal_patterns`) — tunable. Lihat desain §4.
