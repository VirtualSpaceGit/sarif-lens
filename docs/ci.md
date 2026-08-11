# CI guide

SARIF Lens can use a checked-in SARIF file or a compact Lens baseline. A compact baseline keeps only the fields required for identity, review, and policy evaluation.

## GitHub Action

```yaml
name: Security delta

on:
  pull_request:
  push:
    branches: [main]

jobs:
  sarif-lens:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v6

      - name: Produce current SARIF
        run: your-scanner --sarif current.sarif

      - name: Enforce SARIF policy
        id: lens
        uses: VirtualSpaceGit/sarif-lens@v0.1.0
        with:
          baseline: .security/baseline.sarif
          current: current.sarif
          policy: .sarif-lens.json
          report: sarif-lens-report.md

      - name: Archive review report
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: sarif-lens-report
          path: sarif-lens-report.md
```

The action requires Node on the runner. GitHub-hosted runners include a supported Node version.

## Inputs

| Input | Required | Description |
| --- | --- | --- |
| `baseline` | Yes | Baseline SARIF or compact Lens baseline path |
| `current` | Yes | Current SARIF 2.1.0 path |
| `policy` | No | Policy JSON path |
| `fail-on` | No | Severity threshold override |
| `max-new` | No | Maximum finding count override |
| `report` | No | Markdown report path, default `sarif-lens-report.md` |

## Outputs

- `passed`
- `new`
- `updated`
- `fixed`
- `report`

The action also appends the report to the GitHub job summary when `GITHUB_STEP_SUMMARY` is available.

## Baseline lifecycle

A practical baseline workflow is:

1. Review the current report on `main`.
2. Create a compact snapshot with `sarif-lens baseline`.
3. Commit that reviewed snapshot.
4. Compare pull request output against it.
5. Replace it only after the new state is reviewed and accepted.

```bash
npx sarif-lens baseline current.sarif -o .security/sarif-baseline.json
```

Do not update a baseline automatically after a failed gate. That turns a policy decision into an unreviewed build side effect.

## Scanner output stability

For reliable matching:

- Emit stable repository-relative artifact URIs.
- Emit `correlationGuid`, final fingerprints, or versioned partial fingerprints.
- Keep tool name and rule IDs stable.
- Use `automationDetails.id` for logical run identity.
- Give each logical baseline run a stable `automationDetails.guid` and set the corresponding current run `baselineGuid` to that value.
- Do not point `baselineGuid` at the previous top-level run `guid`; SARIF defines the relationship through `automationDetails.guid`.

Use `--strip-prefix` if a runner adds a stable absolute checkout prefix.
