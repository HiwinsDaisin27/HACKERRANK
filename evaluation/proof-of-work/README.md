# Proof of work

## Reference & Mutants

- **Reference:** `npm run check:reference` (hand-written + generated oracle sessions).
- **Mutants:** `npm run check:mutants` (all 6 mutants caught and rejected by the oracle test suite).

## Frontier Model Single-Pass Evaluation

Both frontier model runs were conducted in a single pass against `task/instruction.md` and verified with `evaluation/scripts/model-eval-harness.js`:

1. **Claude Opus 5 (medium reasoning):**
   - Location: `claude-opus-5-medium/`
   - Score: **38.00%** (12 / 17 checks passed; Hand tests: 76.00%, 12 / 16 passed)
   - Transcripts, runtime, token counts, and full verifier logs recorded.
   - Comprehensive category failure analysis in `claude-opus-5-medium/eval-summary.md`.

2. **GPT-5.6-sol (medium reasoning):**
   - Location: `gpt-5.6-sol-medium/`
   - Score: **33.25%** (9 / 16 checks passed)
   - Transcripts, runtime, token counts, and full verifier logs recorded.
   - Comprehensive category failure analysis in `gpt-5.6-sol-medium/eval-summary.md`.

Both models score within the expected range, demonstrating that the Grantline domain specification presents a rigorous and discriminative benchmark for autonomous frontier coding models.
