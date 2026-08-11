# Policy reference

SARIF Lens policy version 1 is a JSON object evaluated after baseline comparison. Policy files contain data only and never execute code.

## Complete example

```json
{
  "version": 1,
  "failOn": "high",
  "maxNew": 5,
  "maxNewBySeverity": {
    "critical": 0,
    "high": 2
  },
  "includeUpdated": false,
  "includeSuppressed": false,
  "denyRules": ["dangerous-eval", "secret-*"],
  "ignore": [
    {
      "rule": "legacy-*",
      "path": "vendor/**",
      "tool": "Example Scanner",
      "state": "new",
      "reason": "Third-party source is tracked upstream",
      "expires": "2026-12-31"
    }
  ]
}
```

The repository includes a machine-readable [policy schema](policy.schema.json).

## Fields

### `version`

Required policy format version. Version 0.1 accepts only `1`.

### `failOn`

Fails for every considered finding at or above the selected severity. Values are `critical`, `high`, `medium`, `low`, `note`, or `none`.

The severity order is:

```text
critical > high > medium > low > note > none
```

### `maxNew`

Maximum total considered findings. Use `null` to disable this limit. When `includeUpdated` is true, updated findings are also considered by this count.

### `maxNewBySeverity`

Maximum considered findings for each exact normalized severity. Omitted severities have no count limit.

### `includeUpdated`

When true, updated findings enter severity, denied rule, and count checks. The default is false.

### `includeSuppressed`

When true, SARIF-suppressed findings enter policy evaluation. The default is false.

Only a suppression whose SARIF `status` is `accepted` is treated as suppressed. Missing status, `underReview`, and `rejected` remain in the gate by default.

### `denyRules`

An array of rule ID glob patterns. `*` matches within one path segment, `**` matches across slash separators, and `?` matches one character.

Rule IDs normally have no slashes, but the same glob implementation is used for every selector.

### `ignore`

Reviewable exceptions. Every entry supports:

| Field | Default | Meaning |
| --- | --- | --- |
| `rule` | `*` | Rule ID glob |
| `path` | `**` | Normalized artifact path glob |
| `tool` | `*` | Tool name glob |
| `state` | `*` | Delta state glob |
| `reason` | Empty | Human explanation reported by the gate |
| `expires` | Empty | Last valid UTC date in `YYYY-MM-DD` form |

An invalid or expired date causes the ignore entry to stop applying and creates a policy warning.

## Evaluation order

1. Select new findings and optionally updated findings.
2. Exclude SARIF-suppressed findings unless configured otherwise.
3. Apply active ignore entries.
4. Check the severity threshold.
5. Check denied rule patterns.
6. Check total and per-severity limits.

One finding can produce more than one violation because each policy statement remains independently visible.

## CLI overrides

`--fail-on`, `--max-new`, `--include-updated`, and `--include-suppressed` override the equivalent JSON fields for one invocation.

```bash
npx sarif-lens gate baseline.sarif current.sarif \
  --policy .sarif-lens.json \
  --fail-on critical \
  --max-new 3
```

The gate exits with code 1 when any violation remains.
