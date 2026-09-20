# Grantline — RL Gym evaluation repository

Headless CLI authorization task for benchmarking autonomous coding agents.

| Path | Purpose |
|------|---------|
| `task/instruction.md` | Model-facing specification (only file agents should rely on) |
| `reference/` | Reference implementation (JSON store; see `reference/STORE_FORMAT.md`) |
| `evaluation/` | Hidden verifier, scoring, mutants, proof-of-work |
| `app-setup/` | `build.sh`, `start.sh`, `reset.sh` lifecycle scripts |

## Commands

```bash
npm install
npm run check:reference   # expect 100%
npm run check:mutants     # all six mutants must score < 100%
npm run score             # score current GRANTLINE_BIN (defaults to reference)
npm run generate          # metadata for an agent evaluation run
```

Set the implementation under test:

```bash
# Unix
export GRANTLINE_BIN="node path/to/grantline.js"

# Windows PowerShell
$env:GRANTLINE_BIN="node path/to/grantline.js"
npm run score
```

Verifier includes hand-written checks plus **400 seeded randomized sessions** (`T-GEN-oracle-sessions`) compared to `reference/` as oracle. Full `npm run check:reference` takes several minutes; set `GENERATED_SESSIONS=80` for faster local runs.

Frontier model proof-of-work is recorded in `evaluation/proof-of-work/` for Claude Opus 5 (medium reasoning) and GPT-5.6-sol (medium reasoning). Runs use `npm run eval:model-record`.

