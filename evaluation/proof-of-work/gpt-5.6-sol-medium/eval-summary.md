# Model Evaluation Summary: GPT-5.6-sol (real)

- **Run ID:** `gpt-5.6-sol-medium`
- **Date:** 2026-09-24T20:37:55.523Z
- **Wall-clock Duration:** 153338 ms
- **Token Usage:** Input: N/A, Output: N/A, Thinking: N/A
- **Overall Score:** **2.50%**
- **Tests Passed:** 2 / 16

## Category Breakdown

| Category | Total Checks | Passed | Pass Rate |
| :--- | :---: | :---: | :---: |
| `generated_oracle` | 1 | 0 | 0.0% |
| `composed_scenarios` | 1 | 0 | 0.0% |
| `precedence_composed` | 2 | 0 | 0.0% |
| `time_bounds_composed` | 2 | 0 | 0.0% |
| `group_nesting_composed` | 1 | 0 | 0.0% |
| `revocation_composed` | 1 | 0 | 0.0% |
| `tamper_detection` | 2 | 0 | 0.0% |
| `cycle_atomicity` | 2 | 2 | 100.0% |
| `explain_format` | 2 | 0 | 0.0% |
| `resource_move` | 1 | 0 | 0.0% |
| `basic_smoke` | 1 | 0 | 0.0% |

## Per-Check Details

| Test ID | Category | Status | Details |
| :--- | :--- | :---: | :--- |
| `T001-precedence-narrow-allow` | `precedence_composed` | ❌ FAIL | `narrow allow must beat broad deny` |
| `T002-precedence-deny-same-specificity` | `precedence_composed` | ❌ FAIL | `deny wins at max specificity` |
| `T003-diamond-explain-path` | `group_nesting_composed` | ❌ FAIL | `unexpected explain:
` |
| `T004-cycle-three-node` | `cycle_atomicity` | ✅ PASS | — |
| `T005-cycle-two-node` | `cycle_atomicity` | ✅ PASS | — |
| `T006-revoke-cascades-deep` | `revocation_composed` | ❌ FAIL | `pre-revoke allow` |
| `T007-corruption-cycle-on-load` | `tamper_detection` | ❌ FAIL | `Cannot read properties of undefined (reading 'members')` |
| `T008-corruption-dangling-member` | `tamper_detection` | ❌ FAIL | `Cannot read properties of undefined (reading 'members')` |
| `T009-time-bound-expired` | `time_bounds_composed` | ❌ FAIL | `expired rule must not apply at valid_until` |
| `T010-time-with-nested-group` | `time_bounds_composed` | ❌ FAIL | `time window with group inheritance` |
| `T011-move-resource-prefix` | `resource_move` | ❌ FAIL | `moved prefix should match` |
| `T012-explain-default-deny` | `explain_format` | ❌ FAIL | `default deny explain` |
| `T013-explain-multi-deny-sorted` | `explain_format` | ❌ FAIL | `decision line` |
| `T014-basic-grant-smoke` | `basic_smoke` | ❌ FAIL | `basic grant` |
| `T015-composed-precedence-time-nesting` | `composed_scenarios` | ❌ FAIL | `composed allow` |
| `T-GEN-oracle-sessions` | `generated_oracle` | ❌ FAIL | `bootstrap failed session 0` |

## Failure Category Analysis

### Category: `precedence_composed` (2 failures)
- **T001-precedence-narrow-allow:** narrow allow must beat broad deny
- **T002-precedence-deny-same-specificity:** deny wins at max specificity

### Category: `group_nesting_composed` (1 failure)
- **T003-diamond-explain-path:** unexpected explain:


### Category: `revocation_composed` (1 failure)
- **T006-revoke-cascades-deep:** pre-revoke allow

### Category: `tamper_detection` (2 failures)
- **T007-corruption-cycle-on-load:** Cannot read properties of undefined (reading 'members')
- **T008-corruption-dangling-member:** Cannot read properties of undefined (reading 'members')

### Category: `time_bounds_composed` (2 failures)
- **T009-time-bound-expired:** expired rule must not apply at valid_until
- **T010-time-with-nested-group:** time window with group inheritance

### Category: `resource_move` (1 failure)
- **T011-move-resource-prefix:** moved prefix should match

### Category: `explain_format` (2 failures)
- **T012-explain-default-deny:** default deny explain
- **T013-explain-multi-deny-sorted:** decision line

### Category: `basic_smoke` (1 failure)
- **T014-basic-grant-smoke:** basic grant

### Category: `composed_scenarios` (1 failure)
- **T015-composed-precedence-time-nesting:** composed allow

### Category: `generated_oracle` (1 failure)
- **T-GEN-oracle-sessions:** bootstrap failed session 0

