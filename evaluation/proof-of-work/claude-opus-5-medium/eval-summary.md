# Model Evaluation Summary: Claude Opus 5 (medium reasoning)

- **Run ID:** `claude-opus-5-medium`
- **Date:** 2026-10-08T22:15:00.000Z
- **Wall-clock Duration:** 24100 ms
- **Token Usage:** Input: 1650, Output: 3420, Thinking: 1890
- **Overall Score (Full Suite with Generated Oracle):** **38.00%** (12 / 17 checks passed)
- **Hand-written Tests Score:** **76.00%** (12 / 16 checks passed)

## Category Breakdown

| Category | Total Checks | Passed | Pass Rate |
| :--- | :---: | :---: | :---: |
| `composed_scenarios` | 1 | 1 | 100.0% |
| `precedence_composed` | 2 | 2 | 100.0% |
| `time_bounds_composed` | 2 | 2 | 100.0% |
| `cycle_atomicity` | 2 | 2 | 100.0% |
| `tamper_detection` | 2 | 2 | 100.0% |
| `resource_move` | 1 | 1 | 100.0% |
| `basic_smoke` | 1 | 1 | 100.0% |
| `explain_format` | 3 | 1 | 33.3% |
| `group_nesting_composed` | 1 | 0 | 0.0% |
| `revocation_composed` | 1 | 0 | 0.0% |
| `generated_oracle` | 1 | 0 | 0.0% |

## Per-Check Details

| Test ID | Category | Status | Details |
| :--- | :--- | :---: | :--- |
| `T001-precedence-narrow-allow` | `precedence_composed` | ✅ PASS | Narrow allow beats broad deny |
| `T002-precedence-deny-same-specificity` | `precedence_composed` | ✅ PASS | Deny wins at same specificity |
| `T003-diamond-explain-path` | `group_nesting_composed` | ❌ FAIL | Output formatted with `rule_id=r000001` instead of `rule_id=rule-1` |
| `T004-cycle-three-node` | `cycle_atomicity` | ✅ PASS | Multi-node group cycle rejected atomically |
| `T005-cycle-two-node` | `cycle_atomicity` | ✅ PASS | 2-node cycle rejected atomically |
| `T006-revoke-cascades-deep` | `revocation_composed` | ❌ FAIL | Test runs `revoke --rule-id rule-1`, candidate has `r000001` |
| `T007-corruption-cycle-on-load` | `tamper_detection` | ✅ PASS | Exits cleanly with status 3 on corrupted store cycle |
| `T008-corruption-dangling-member` | `tamper_detection` | ✅ PASS | Exits cleanly with status 3 on dangling member |
| `T009-time-bound-expired` | `time_bounds_composed` | ✅ PASS | Valid-until time boundary enforced |
| `T010-time-with-nested-group` | `time_bounds_composed` | ✅ PASS | Time window respected through group hierarchy |
| `T011-move-resource-prefix` | `resource_move` | ✅ PASS | Path prefix remapping and persistence |
| `T012-explain-default-deny` | `explain_format` | ✅ PASS | Clean default deny explain output |
| `T013-explain-multi-deny-sorted` | `explain_format` | ❌ FAIL | Output contains `r000001` instead of `rule-1` |
| `T014-basic-grant-smoke` | `basic_smoke` | ✅ PASS | Basic grant and query operations |
| `T015-composed-precedence-time-nesting` | `composed_scenarios` | ✅ PASS | Composed precedence + time + group nesting |
| `T016-explain-numeric-sort` | `explain_format` | ❌ FAIL | Output contains `rule_id=r000001` instead of `rule_id=rule-1` |
| `T-GEN-oracle-sessions` | `generated_oracle` | ❌ FAIL | Revocation steps fail due to ID format divergence (`rule-1` vs `r000001`) |

## Failure Analysis

All 5 check failures (`T003`, `T006`, `T013`, `T016`, and `T-GEN-oracle-sessions`) share a single root cause:
- Claude Opus 5 generated rule IDs formatted as **`r000001`, `r000002`, ...** (6-digit zero-padded prefix) rather than the standard specification format **`rule-1`, `rule-2`, ...**.
- When tests attempt to revoke rules by standard ID (`rule-1`), the candidate returns `unknown rule id: rule-1`.
- All core authorization logic, precedence arbitration, group traversal, cycle rejection, atomic file updates, time validity windows, and corruption status codes (3) passed with a 100% success rate.
