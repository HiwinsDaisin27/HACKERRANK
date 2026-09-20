# Proof of work

## Reference & Mutants

- **Reference:** `npm run check:reference` (hand-written + generated oracle sessions).
- **Mutants:** `npm run check:mutants` (all 6 mutants caught and rejected by the oracle test suite).

## Frontier Model Single-Pass Evaluation

Both frontier model runs were conducted in a single pass against `task/instruction.md` and verified with `evaluation/scripts/model-eval-harness.js`:

1. **Claude Opus 5 (medium reasoning):**
   - Location: `claude-opus-5-medium/`
   - Score: **0.00%** (0 / 16 checks passed)
   - Transcripts, runtime, token counts, and full verifier logs recorded.
   - Comprehensive category failure analysis in `claude-opus-5-medium/eval-summary.md`.

2. **GPT-5.6-sol (medium reasoning):**
   - Location: `gpt-5.6-sol-medium/`
   - Score: **0.00%** (0 / 16 checks passed)
   - Transcripts, runtime, token counts, and full verifier logs recorded.
   - Comprehensive category failure analysis in `gpt-5.6-sol-medium/eval-summary.md`.

Both models score well below the required threshold (≤ 30%), demonstrating that the Grantline domain specification presents a challenging benchmark for autonomous frontier coding models.

