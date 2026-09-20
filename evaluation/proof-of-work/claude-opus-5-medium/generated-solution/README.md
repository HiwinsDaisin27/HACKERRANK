# grantline

A headless command-line authorization engine. Each invocation loads a JSON
store from disk, performs exactly one operation, and exits.

## Install

```sh
npm install -g .
# or run directly:
node grantline.js ...
```

## Store format

The store is a single JSON file. Missing files are treated as empty.

```json
{
  "nextRuleId": 3,
  "principals": ["alice", "bob"],
  "groups": {
    "team":     { "members": ["alice", "subteam"] },
    "subteam":  { "members": ["bob"] }
  },
  "resources": ["/app", "/app/secrets"],
  "rules": [
    {
      "id": 1,
      "target": "team",
      "action": "read",
      "resource": "/app",
      "effect": "deny",
      "valid_from": null,
      "valid_until": null
    }
  ]
}
```

## Commands

All commands accept `--store <path>` (required).

### Principals
```
grantline principal create <id> --store <path>
grantline principal delete <id> --store <path>
grantline principal list        --store <path>
```

### Groups
```
grantline group create <id>                            --store <path>
grantline group delete <id>                            --store <path>
grantline group add-member <group> <member>            --store <path>
grantline group remove-member <group> <member>         --store <path>
grantline group list                                   --store <path>
```

`<member>` is a principal id or another group id. Cycles are rejected.

### Resources
```
grantline resource create <path>  --store <path>
grantline resource delete <path>  --store <path>
grantline resource list           --store <path>
```

### Rules
```
grantline rule add <target> <action> <resource> <effect> \
    [--valid-from <iso>] [--valid-until <iso>] --store <path>
grantline rule remove <id>  --store <path>
grantline rule list         --store <path>
```

* `<target>`     — principal id or group id
* `<action>`     — `read` | `write` | `admin`
* `<resource>`   — resource path, e.g. `/finance/reports`
* `<effect>`     — `allow` | `deny`

`rule add` prints the newly allocated rule id on stdout.

### Queries
```
grantline query   <principal> <action> <resource> [--at <iso>] --store <path>
grantline explain <principal> <action> <resource> [--at <iso>] --store <path>
```

`query` prints `ALLOW` or `DENY`. `explain` prints a JSON report showing the
applicable rules, their specificity, and which rules won.

If `--at` is omitted the system clock is used.

## Decision model

1. **Applicability.** A rule can see a request when:
   - its target is the requesting principal, or a group the principal
     belongs to (directly or transitively);
   - its resource path equals the request path or is an ancestor;
   - its action equals the request action;
   - its time window contains **T** (`T >= valid_from` if set,
     `T < valid_until` if set).

2. **Specificity.** Deeper (more segment-rich) rule paths outrank shallower
   ones. The root `/` is treated as one segment; `/app` and `/` are at the
   same depth; `/app/config` is deeper than `/app`.

3. **Allow vs. deny at the same specificity.** Deny wins.

4. **Default deny.** No applicable rule ⇒ `DENY`.

## Exit codes

| Code | Meaning                                     |
|------|---------------------------------------------|
| 0    | Success                                     |
| 1    | General failure (`grantline: <message>`)    |
| 3    | Store corruption                            |

On failure, the store file is left byte-identical to its previous state.
Mutating commands write atomically (temp file + `rename`).
