# Grantline — authorization CLI

Build a headless command-line program named **grantline** that answers authorization questions over a persistent store of principals, groups, resources, and permission rules. Each process invocation loads the store from disk, performs exactly one operation, writes any outputs, updates the store only when the operation is a successful mutation, and exits. There is no server, daemon, network access, or background work.

You may choose any on-disk persistence format, provided the observable behaviors below are satisfied.

## Domain model

- **Principals** are individual identities (ids: letters, digits, `.`, `_`, `-`).
- **Groups** are named collections with the same id rules. Members may be principals or other groups (nesting to arbitrary depth).
- **Resources** are hierarchical paths (`/finance/reports/q3`). Paths start with `/`, have no empty segments, and no trailing slash except `/`. Path `/a` applies to itself and every path that extends it with more segments (`/a/b`, `/a/b/c`, …).
- **Rules** attach to a **target** (one principal or one group) and govern an **action** on a **resource path**. Actions: `read`, `write`, `admin`. Effect: `allow` or `deny`. A principal **inherits** rules that target any group they belong to, including through nested groups.

### Time-bounded rules

Rules may include optional ISO 8601 timestamps:

- **`valid_from`** — if absent, the rule is active from the beginning of time.
- **`valid_until`** — if absent, the rule never expires.

At evaluation instant **T**, a rule is **in effect** only when `T` is inside its window: at or after `valid_from` (if set), and **strictly before** `valid_until` (if set).

**Membership is immediate, not time-windowed.** Changing group membership affects later queries right away; it does not add or remove temporal bounds on existing rules. Only each rule’s own timestamps control that rule’s lifetime.

### Default deny

If nothing applicable authorizes the action under the rules below, the answer is **DENY**.

## How decisions are made (behavioral contract)

Think in terms of **which rules can “see” the request**, then **which of those win**. Evaluation instant **T** comes from `--at` on `query` / `explain`, or the system clock if omitted.

**Applicability.** A rule can affect a request when all of the following hold:

- The request’s principal is the rule’s target, **or** belongs to the target group (directly or through nesting).
- The rule’s resource path is the same as the requested resource, or is an **ancestor** path (the request path is the rule path or lives under it).
- The rule’s action matches the requested action.
- The rule is **in effect** at **T** (see time bounds above).

**Specificity.** When several applicable rules compete, a rule tied to a **more specific** (deeper) resource path outranks a rule tied to a broader ancestor path. Treat `/` as the broadest path (one segment). For example, `/app` and `/` both have a single segment; `/app/config` is more specific than `/app`.

**Allow vs deny at the same specificity.** If the winning specificity level includes both allow and deny rules, **deny wins**.

**No applicable rule → DENY.**

### Worked examples (results only)

Assume principal `alice` is in group `team`, all rules are active at the query time, and queries use the stated action implicitly.

| Situation | Query | Result |
|-----------|-------|--------|
| Deny on `/app` for `team`; allow on `/app/secrets` for `team` | `alice` reads `/app/secrets/key` | **ALLOW** (deeper allow beats broader deny) |
| Allow on `/data` for `alice`; deny on `/data` for `team` | `alice` writes `/data/x` | **DENY** (same depth, deny beats allow) |
| Allow on `/tmp` for `team` only | `alice` reads `/tmp/x` | **ALLOW** (inherited via group) |
| Allow on `/a` with `valid_until` = `2025-06-01T00:00:00Z` | `alice` reads `/a/x` at `2025-06-01T00:00:00Z` | **DENY** (instant `T` must be **strictly before** `valid_until`) |
| Same rule | `alice` reads `/a/x` at `2025-05-31T23:59:59Z` | **ALLOW** |
| No rule applies | `alice` reads `/unknown` | **DENY** |

## CLI

All commands take `--store <path>`. Successful mutations exit `0`. Failed mutations exit non-zero and must **not change** the store file on disk (byte-identical to before the invocation).

**Corruption:** If the store is structurally invalid (see below), every command exits **`3`** with stderr exactly:

`grantline: store corruption detected: <reason>`

No stdout in that case. Other failures use exit **`1`** and stderr `grantline: <message>`.

```
grantline init --store <path>
grantline add-principal --store <path> --id <id>
grantline add-group --store <path> --id <id>
grantline add-group-member --store <path> --group <id> --member <id>
grantline remove-group-member --store <path> --group <id> --member <id>
grantline grant --store <path> --principal-or-group <id> --resource <path> --action <read|write|admin> [--valid-from <ts>] [--valid-until <ts>]
grantline deny --store <path> --principal-or-group <id> --resource <path> --action <read|write|admin> [--valid-from <ts>] [--valid-until <ts>]
grantline revoke --store <path> --rule-id <id>
grantline query --store <path> --principal <id> --resource <path> --action <read|write|admin> [--at <ts>]
grantline explain --store <path> --principal <id> --resource <path> --action <read|write|admin> [--at <ts>]
grantline move-resource --store <path> --from <path> --to <path>
```

- **`init`** — empty store at a fresh path.
- **`add-principal` / `add-group`** — reject duplicates; group ids must not collide with principal ids.
- **`add-group-member`** — member must exist; reject duplicate membership; **reject any group nesting that would create a cycle** (including cycles longer than two groups).
- **`remove-group-member`** — reject if not a direct member.
- **`grant` / `deny`** — target must exist; paths and actions must be valid; if both time bounds are set, `valid_from` must be earlier than `valid_until`. Rule ids are assigned sequentially as `rule-1`, `rule-2`, `rule-3`, … in creation order (1-indexed across all rules created in the store). Rule ids are never reused or re-indexed after a rule is revoked.
- **`revoke`** — remove rule by id; after success, **all** principals must immediately reflect the removal, including via nested groups.
- **`query`** — print exactly `ALLOW` or `DENY` plus a newline, nothing else.
- **`move-resource`** — rewrite every rule whose resource equals `--from` or sits under `--from/…` by swapping that prefix for `--to`. Reject if `--from` equals `--to` or nothing would change.

## `explain` output format

Stdout must end with a newline.

- Line 1: `DECISION: ALLOW` or `DECISION: DENY` — must agree with `query` for the same arguments.
- If the decision is **DENY** because nothing applied, or **ALLOW**/**DENY** with no rules left at the winning specificity after applying the behavioral contract above, print one line: `MATCH: none`.
- Otherwise, for **each** rule at the winning specificity that determined the outcome (all winning denies when the decision is DENY; all winning allows when ALLOW), one line:

`MATCH: rule_id=<id> effect=<allow|deny> action=<action> resource=<path> specificity=<n> target_type=<principal|group> target_id=<id>`

For `target_type=group`, append ` membership_path=<chain>` where `<chain>` is group ids joined by `>` from the rule’s target group down to a group that **directly** lists the queried principal. If several chains exist (diamond), use the **lexicographically smallest** chain.

Sort `MATCH:` lines by the numeric suffix of `rule_id` in ascending order (`rule-1`, `rule-2`, …, `rule-9`, `rule-10`, `rule-11`). Use single spaces as shown; no trailing spaces on lines.

**Specificity** in the output is the segment count of the rule’s resource path (`/` → `1`, `/finance/reports` → `2`).

## Store integrity

On **every** command, validate before acting:

- Well-formed storage for your format.
- No dangling members or rule targets.
- No cycles in the group→nested-group graph.

Invalid store → exit **3** as above; do not mutate the file; do not answer ALLOW/DENY.

The store file may be edited externally between invocations; you must detect invalid states and refuse service rather than guess.

## Atomicity

Any rejected mutation (validation, cycle, duplicate, bad timestamps, move with no effect, etc.) leaves the on-disk store **unchanged** for that invocation.

## Deliverable

Ship an executable **`grantline`** command (script or binary) that the project build scripts can invoke on `PATH`.
