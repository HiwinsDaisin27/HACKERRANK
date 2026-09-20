# Mutant kill matrix

Each mutant must fail the **generated oracle** layer (`runGeneratedOracleSuite`, compared against `reference/`). Hand-written checks are supplementary.

| Mutant | Bug | Hand-written checks | Generated oracle |
|--------|-----|---------------------|------------------|
| `mutant-1-precedence-order` | Deny-first across all matches, then specificity | `T001`, `T015` | Precedence/query drift in random sessions |
| `mutant-2-shallow-cycle` | Only detects 2-node cycles | `T004` | 3-cycle attempt + store divergence |
| `mutant-3-stale-revocation-cache` | Disk query cache not invalidated on revoke | `T006` | Revoke then query in same session |
| `mutant-4-non-atomic-cycle` | Writes membership before cycle validation | `T004`, `T005` | Cycle attempt leaves store diverged |
| `mutant-5-no-corruption-check` | Skips integrity validation on load | `T007` | Tampered store query exit mismatch |
| `mutant-6-ignore-time-bounds` | Ignores `--at` / validity windows | `T009`, `T010`, `T015` | Random `--at` queries |

Run: `npm run check:mutants` (uses `MUTANT_GENERATED_SESSIONS`, default 50).

Summary: `mutant-run-summary.json`.
