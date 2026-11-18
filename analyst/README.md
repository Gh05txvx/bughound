# bughound-analyst

Triage + **decision support (SAW)** + **what-if** over BugHound findings. A **separate**
app from the BugHound core. **Read-only** (just `GET /api/v1/findings`): it never triggers
a scan/submit. AI = advisor; **the validation in Burp = a human**.

> Full design: [`docs/BH-DESIGN-analyst-spk.md`](docs/BH-DESIGN-analyst-spk.md).

## Flow

```
BugHound ─GET /api/v1/findings─▶ ingest → analyst(cluster,FP,derived) → SAW(ranking) → what-if(scaffold)
(read-only)                                                                                   │
                                                                              you + Burp Repeater (manual)
```

## Install

```bash
python -m venv .venv && . .venv/Scripts/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env    # fill in BUGHOUND_URL/USER/PASS (a viewer account is enough)
```

## Use

**Test (no network):**
```bash
python tests/test_saw.py        # or: pytest
```

**As an MCP server (for Claude):**
```bash
python server.py                # tools: rank(program, top), whatif(program, finding_id)
```
> Needs the MCP SDK. `mcp>=2` renames `FastMCP` to `MCPServer`; `server.py` supports
> both (2.x preferred, 1.x fallback). Credentials are read from `.env` **next to
> `server.py`** (so they are read even when the client calls from another cwd).

Register it with an MCP client as the `bughound-analyst` server (change the path for your machine):

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

Claude calls `rank` to get the SAW ranking; `whatif` to get the scaffold + scrubbed evidence,
then Claude writes the `hypotheses`/`why`. **You** are the one who runs it in Burp.

## Components

| Module | Content |
|---|---|
| `bughound_analyst/client.py` | read-only API client (Basic) |
| `bughound_analyst/model.py` | `Finding` from the BugHound schema JSON |
| `bughound_analyst/analyst.py` | cluster, fp_likelihood, derived, prefilter (deterministic) |
| `bughound_analyst/saw.py` | **SAW**: normalize + score + ranking (explainable) |
| `bughound_analyst/scrub.py` | redact evidence before the LLM |
| `bughound_analyst/whatif.py` | plan scaffold (hypotheses filled by the LLM) |
| `bughound_analyst/config.py` + `weights.yaml` | weights & mapping, **tunable** |
| `server.py` | MCP server |

## Safe by design

- **Read-only**: no tool changes state or touches a target.
- **The numbers come from code**, not the LLM (SAW/cluster/FP are deterministic & tested).
- **Evidence is scrubbed** before it reaches the LLM (`scrub.py`): credentials/PII become `[REDACTED]`.
- What-if = a **suggestion**; never auto-executed. Burp is run by a human, within RoE.

## Decision-support tuning

Edit `weights.yaml` (Σ weights = 1.0, validated at load). 8 criteria: exploitability,
**signal** (payout per class, anti header-noise), bounty, severity, fp_likelihood (cost),
effort (cost), owasp, freshness. The signal classification patterns (high/noise) are also in
`weights.yaml` (`signal_patterns`), tunable. See design §4.
