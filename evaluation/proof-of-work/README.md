# Proof of work

## Completed internally

- **Reference:** `npm run check:reference` (hand-written + generated oracle sessions).
- **Mutants:** `npm run check:mutants` (must fail generated layer, not only fixed scenarios).

## Frontier model evaluation — not run yet

Real single-pass runs for **Claude Opus 5 (medium reasoning)** and **GPT-5.6-sol (medium reasoning)** are **pending**. Do not submit until:

1. Instruction hardening and generated oracle verifier are in place (internal).
2. Each model is evaluated once with only `task/instruction.md`, with full transcripts and token/runtime metadata via `evaluation/scripts/model-eval-harness.js`.

Placeholder directories (no scores, no fabricated logs):

- `claude-opus-5-medium/`
- `gpt-5.6-sol-medium/`

Previously fabricated stub agents were moved to `evaluation/_quarantine/fabricated-model-proof-of-work/` and must never be used as proof-of-work.
