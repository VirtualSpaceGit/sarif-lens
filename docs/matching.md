# Matching model

SARIF Lens compares finding instances, not only totals by rule. Its goal is to preserve stable identity across normal source movement while refusing matches that are not defensible.

The implementation is deterministic. The same inputs and options produce the same pairing, ordering, and JSON output.

## Run pairing

Results are matched only inside paired analysis runs. SARIF Lens pairs runs in this order:

1. The current run `baselineGuid` equals the baseline run `automationDetails.guid`.
2. `automationDetails.id` and tool name are equal.
3. Tool name and run index are equal.
4. A tool name occurs exactly once on each side.

At every stage, a run pair is accepted only when each run has exactly one candidate from both directions. One-to-many, many-to-one, and many-to-many candidate collisions are refused and produce matching notes. Each run can be paired once. Results in an unpaired baseline run become fixed. Results in an unpaired current run become new.

This follows the SARIF baseline relationship: a current run points to the previous run's `automationDetails.guid`. The top-level run `guid` identifies a run execution and is not the target of `baselineGuid`.

## Result identity

Every result key is scoped by normalized tool name and rule ID. Within that scope, SARIF Lens tries these strategies in order:

1. Exact `correlationGuid`
2. Exact common entry in `fingerprints`
3. Exact common entry in `partialFingerprints`
4. Normalized source snippet plus artifact path
5. Normalized message plus artifact path
6. Artifact path plus line as a compatibility fallback

Matching is one to one. At every strategy, a result match is accepted only when the baseline result has exactly one current candidate and that current result has exactly one baseline candidate.

Snippet, message, and location fallbacks are generated only when a result has no producer correlation GUID, final fingerprint, or partial fingerprint. Conflicting producer identities are never overridden by weaker text or location similarity.

If a baseline key has multiple current candidates, a current key has multiple baseline candidates, or both sides collide at a matching stage, SARIF Lens refuses that stage and records the ambiguity. It does not merge duplicate results or choose the first one.

## Path normalization

Artifact paths are normalized before identity keys are built:

- Backslashes become forward slashes.
- A leading `./` is removed.
- Duplicate slashes are collapsed.
- File URI prefixes are removed.
- Valid percent escapes are decoded.
- User supplied `--strip-prefix` values can remove changing checkout roots.

Path case is normalized only inside identity keys. The original normalized path remains available for display.

`uriBaseId` is retained in the normalized finding, but version 0.1 does not resolve `originalUriBaseIds` into a full artifact URI. Producers should emit stable repository-relative artifact URIs whenever possible.

## Why line numbers are last

An inserted comment or import can move many findings without changing the underlying problems. Absolute line numbers are therefore not primary identity. They are used only by the final low-confidence compatibility fallback.

This follows the SARIF guidance that producer partial fingerprints should survive source movement and should not rely on absolute line position. See the [OASIS SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) and [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

## Delta states

Every finding instance receives one state:

- `new`: no baseline result was matched
- `fixed`: no current result was matched
- `updated`: a matched result changed in a significant field
- `unchanged`: a matched result has no significant change

SARIF uses `absent` for results missing from the current run. SARIF Lens calls that state `fixed` in its review UI and maps it back to `absent` when exporting SARIF.

Significant update fields in version 0.1 are:

- Severity
- Message
- Artifact path
- Source snippet
- CWE set
- Suppression state

Line and column differences are recorded as movement. Movement alone does not make a result updated.

## Confidence and explanation

Matched diff items expose:

- `strategy`: the evidence that paired the results
- `confidence`: exact, high, medium, or low
- `runPairStrategy`: the evidence that paired their runs
- `changes.significant`: fields that made the result updated
- `changes.movement`: line or column movement

The browser detail view displays these values, and JSON output preserves them for automation.

## Known limits

- Versioned fingerprint names are compared as exact names. Selection of the latest common numeric version is planned.
- `originalUriBaseIds` and Git rename maps are not resolved in version 0.1.
- Snippet and message fallbacks require the artifact path to remain stable.
- The final path and line fallback is deliberately low confidence.
- This is tolerant structural parsing, not full SARIF JSON Schema validation.
- A malicious or broken producer can emit misleading fingerprints. Explainable output helps reviewers detect that, but cannot prove producer correctness.

If a match affects a release gate and the confidence is not acceptable, improve the scanner fingerprints or use stable paths instead of adding a fuzzy exception.
