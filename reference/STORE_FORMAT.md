# Grantline on-disk store format (reference implementation)

The reference implementation persists state as a single JSON file.

## Top-level schema

```json
{
  "version": 1,
  "principals": ["alice"],
  "groups": {
    "eng": {
      "members": ["alice", "backend"]
    }
  },
  "rules": [
    {
      "id": "rule-1",
      "target_type": "group",
      "target_id": "eng",
      "resource": "/finance/reports",
      "action": "read",
      "effect": "allow",
      "valid_from": null,
      "valid_until": "2025-06-01T00:00:00Z"
    }
  ],
  "next_rule_seq": 2
}
```

- `version`: must be `1`.
- `principals`: sorted unique strings.
- `groups`: map of group id → `{ "members": string[] }` (member ids are principal or nested group ids).
- `rules`: array of rule objects.
- `next_rule_seq`: monotonic counter for generating `rule-<n>` ids.

## Rule object

| Field | Type | Notes |
|-------|------|--------|
| `id` | string | Unique, e.g. `rule-7` |
| `target_type` | `"principal"` \| `"group"` | |
| `target_id` | string | Must exist at write time |
| `resource` | string | Absolute path, starts with `/`, no trailing slash except `/` |
| `action` | `"read"` \| `"write"` \| `"admin"` | |
| `effect` | `"allow"` \| `"deny"` | |
| `valid_from` | ISO 8601 string or `null` | null = valid since beginning of time |
| `valid_until` | ISO 8601 string or `null` | null = no expiry |

## Corruption checks on every load

Before serving any command (including read-only `query` / `explain`), the tool validates:

1. Valid JSON and `version === 1`.
2. Every group member references an existing principal or group.
3. Every rule `target_id` references an existing principal (if `target_type` is principal) or group.
4. The directed graph of groups (edge: group → member when member is a group) has no cycles.

On failure: exit code `3`, stderr line `grantline: store corruption detected: <reason>`.

## Atomic writes

Mutations validate in memory, then write the full file via temp file + rename.
