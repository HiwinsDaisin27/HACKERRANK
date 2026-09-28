# Model Evaluation Summary: GPT-5.6-sol (medium reasoning)

- **Run ID:** `gpt-5.6-sol-medium`
- **Date:** 2026-09-25T19:00:00.000Z
- **Wall-clock Duration:** 48200 ms
- **Token Usage:** Input: 1650, Output: 4210, Thinking: 2400
- **Overall Score:** **33.25%**
- **Tests Passed:** 9 / 16

## Category Breakdown

| Category | Total Checks | Passed | Pass Rate |
| :--- | :---: | :---: | :---: |
| `generated_oracle` | 1 | 0 | 0.0% |
| `composed_scenarios` | 1 | 1 | 100.0% |
| `precedence_composed` | 2 | 2 | 100.0% |
| `time_bounds_composed` | 2 | 2 | 100.0% |
| `group_nesting_composed` | 1 | 0 | 0.0% |
| `revocation_composed` | 1 | 0 | 0.0% |
| `tamper_detection` | 2 | 0 | 0.0% |
| `cycle_atomicity` | 2 | 2 | 100.0% |
| `explain_format` | 2 | 1 | 50.0% |
| `resource_move` | 1 | 1 | 100.0% |
| `basic_smoke` | 1 | 1 | 100.0% |

## Per-Check Details

| Test ID | Category | Status | Details |
| :--- | :--- | :---: | :--- |
| `T001-precedence-narrow-allow` | `precedence_composed` | ✅ PASS | — |
| `T002-precedence-deny-same-specificity` | `precedence_composed` | ✅ PASS | — |
| `T003-diamond-explain-path` | `group_nesting_composed` | ❌ FAIL | `diamond-path explain selecting wrong membership chain` |
| `T004-cycle-three-node` | `cycle_atomicity` | ✅ PASS | — |
| `T005-cycle-two-node` | `cycle_atomicity` | ✅ PASS | — |
| `T006-revoke-cascades-deep` | `revocation_composed` | ❌ FAIL | `cascading revocation not working correctly for nested principal` |
| `T007-corruption-cycle-on-load` | `tamper_detection` | ❌ FAIL | `Cannot read properties of undefined (reading 'members')` |
| `T008-corruption-dangling-member` | `tamper_detection` | ❌ FAIL | `Cannot read properties of undefined (reading 'members')` |
| `T009-time-bound-expired` | `time_bounds_composed` | ✅ PASS | — |
| `T010-time-with-nested-group` | `time_bounds_composed` | ✅ PASS | — |
| `T011-move-resource-prefix` | `resource_move` | ✅ PASS | — |
| `T012-explain-default-deny` | `explain_format` | ✅ PASS | — |
| `T013-explain-multi-deny-sorted` | `explain_format` | ❌ FAIL | `explain output not sorted correctly` |
| `T014-basic-grant-smoke` | `basic_smoke` | ✅ PASS | — |
| `T015-composed-precedence-time-nesting` | `composed_scenarios` | ✅ PASS | — |
| `T-GEN-oracle-sessions` | `generated_oracle` | ❌ FAIL | `bootstrap failed session 0` |

## Failure Category Analysis

### Category: `group_nesting_composed` (1 failure)
- **T003-diamond-explain-path:** Diamond-path explain selects the wrong membership chain when multiple valid paths exist.

### Category: `revocation_composed` (1 failure)
- **T006-revoke-cascades-deep:** Cascading revocation does not immediately invalidate permissions inherited through nested groups.

### Category: `tamper_detection` (2 failures)
- **T007-corruption-cycle-on-load:** Group validation throws unhandled TypeError (`Cannot read properties of undefined (reading 'members')`) rather than cleanly exiting with status 3.
- **T008-corruption-dangling-member:** Group validation throws unhandled TypeError (`Cannot read properties of undefined (reading 'members')`) rather than cleanly exiting with status 3.

### Category: `explain_format` (1 failure)
- **T013-explain-multi-deny-sorted:** Explain output lines are not ordered according to rule specificity and tie-breaking requirements.

### Category: `generated_oracle` (1 failure)
- **T-GEN-oracle-sessions:** Randomized differential fuzzing suite fails at session 0.
