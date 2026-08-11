# SARIF Lens Research

Research date: 2026-08-11

## Executive conclusion

SARIF Lens should be positioned as an offline review, diff, and policy gate for SARIF, not as another SARIF viewer.

The strongest product promise is:

> Review, diff, and gate any SARIF report. Fully local.

This positioning closes a complete workflow:

1. Inspect findings from any SARIF-producing tool.
2. Compare a current report with a baseline at finding-instance level.
3. Understand why findings matched, moved, changed, appeared, or disappeared.
4. Enforce the same policy locally and in CI.

Existing projects already render SARIF well, manipulate it from a command line, or display it inside an editor. The clearest underserved area is the combination of explainable stable matching, interactive comparison, and tool-neutral policy gates backed by one shared engine.

Stars cannot be guaranteed. GitHub stars depend on utility, execution quality, maintenance, distribution, timing, and community attention. The research supports a credible opportunity for useful adoption, not a promise of a particular star count.

## Primary-source market snapshot

Star counts below are a point-in-time snapshot from 2026-08-11. They will change.

| Project | Stars | What the primary source shows | Lesson for SARIF Lens |
| --- | ---: | --- | --- |
| [microsoft/sarif-sdk](https://github.com/microsoft/sarif-sdk) | 224 | A mature .NET object model and supporting tools for SARIF. The related [Sarif.Multitool package](https://www.nuget.org/packages/Sarif.Multitool) reports roughly 800,000 total downloads. | Parsing, validation, manipulation, and baseline-oriented plumbing already exist. A new project needs a clearer user outcome. |
| [microsoft/sarif-tools](https://github.com/microsoft/sarif-tools) | 155 | A Python CLI with inspection, diff, filtering, HTML, CSV, trend, and simple CI checks. | A command list alone is not a unique position. Its documented diff limitations create a specific opening for better instance matching. |
| [microsoft/sarif-vscode-extension](https://github.com/microsoft/sarif-vscode-extension) | 139 | A polished VS Code viewer with source squiggles, Problems integration, grouping, filtering, URI reconciliation, and a dedicated results panel. | Editor-native viewing is already served. Browser access and CI policy need to be first-class rather than secondary. |
| [microsoft/sarif-web-component](https://github.com/microsoft/sarif-web-component) | 108 | A reusable React component for viewing SARIF logs. | Rendering is available as a component. SARIF Lens must provide an end-to-end workflow, not only a better table. |
| [trailofbits/vscode-sarif-explorer](https://github.com/trailofbits/vscode-sarif-explorer) | 53 | Multi-file triage, data-flow browsing, classification, comments, filters, and a shareable review-state file in VS Code. | Human triage is valuable, but durable result identity remains difficult and is a strong differentiation opportunity. |
| [microsoft/sarif-visualstudio-extension](https://github.com/microsoft/sarif-visualstudio-extension) | 49 | A Visual Studio viewer for SARIF logs. | Another viewer competes in an established, relatively narrow category. |
| [reviewdog/reviewdog](https://github.com/reviewdog/reviewdog) | 9,517 | A tool-neutral review workflow that accepts SARIF, filters findings against code changes, and reports to multiple code hosts. | The strongest adjacent adoption signal is workflow completion and integration, not format handling by itself. |

The direct SARIF projects mostly sit in the tens to low hundreds of stars. This does not mean a SARIF project cannot grow beyond that range. It does mean that calling the project a viewer and shipping only rendering would place it in a proven but limited category.

## Direct competition and the remaining gap

### Microsoft SARIF Tools

[Microsoft SARIF Tools](https://github.com/microsoft/sarif-tools) is the closest direct CLI comparison. It can inspect report structure, compare files or directories, filter findings, create portable HTML, emit other formats, and fail CI based on severity.

Its own documentation describes an important limitation. When the occurrence count for an issue code is unchanged, the diff does not report the code even if an equal number of instances were fixed and introduced. It also notes that changed line numbers can produce false positives.

That is the precise problem SARIF Lens should solve. A reliable comparison must identify finding instances, not only compare totals by rule and severity.

### Microsoft SARIF SDK and Multitool

[Microsoft SARIF SDK](https://github.com/microsoft/sarif-sdk) and [Sarif.Multitool](https://www.nuget.org/packages/Sarif.Multitool) are mature foundations for reading, validating, analyzing, and manipulating SARIF. Their existence means SARIF Lens should not claim that SARIF processing or baseline matching is new.

The differentiation is the integrated experience:

- A browser workbench that makes matching and policy decisions visible.
- A Node CLI with the exact same counts and decisions.
- An explainable result-identity model.
- A declarative policy format designed for local use and CI.

### Microsoft editor and web viewers

The [Microsoft VS Code extension](https://github.com/microsoft/sarif-vscode-extension) is strong inside an editor. The [Microsoft web component](https://github.com/microsoft/sarif-web-component) is a useful renderer for developers building their own applications. Neither is positioned as a complete browser-to-CI baseline and policy workflow.

SARIF Lens should therefore avoid competing on generic features such as sorting, dark mode, or a prettier result list. Those are expected product quality. The differentiating experience starts when the user drops in two reports and receives an explainable, policy-ready delta.

### Trail of Bits SARIF Explorer

[SARIF Explorer](https://github.com/trailofbits/vscode-sarif-explorer) demonstrates that analysts value classification, comments, filters, multi-file review, and data-flow navigation.

Its [review-state format documentation](https://github.com/trailofbits/vscode-sarif-explorer/blob/HEAD/docs/sarif_explorer_spec.md) also documents a result-identity problem. Review state is keyed by run and result indexes, which can become desynchronized when a report changes. The document notes that an earlier fingerprint approach encountered tools that emitted duplicate fingerprints.

This is strong primary-source evidence for collision-safe, one-to-one matching and for an `explain-match` capability. A fingerprint should be evidence used during matching, not blindly treated as a globally unique identifier.

### New offline viewers

The recently published [ndaal SARIF Viewer](https://docs.rs/crate/sarif-viewer/latest) already offers a self-contained offline viewer, schema validation, a local web interface, hardened serving, and multiple export formats.

This removes offline viewing by itself as a durable differentiator. SARIF Lens needs baseline comparison, matching transparency, and policy evaluation to own a distinct outcome.

### GitHub code scanning

[GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support) is both a competitor and a source of interoperability requirements.

GitHub documents that:

- Fingerprints are used to prevent duplicate alerts across runs.
- Inconsistent file paths can cause duplicate alert churn.
- `partialFingerprints` are used to identify logically identical results.
- GitHub consumes a supported subset of SARIF 2.1.0.
- Code scanning is available for public repositories and for eligible organization repositories with GitHub Code Security enabled.
- Uploads have limits, including 10 MB compressed, 20 runs per file, and 25,000 results per run, with only the top 5,000 displayed.

Those constraints create demand for a local, host-independent workbench. They also justify a GitHub compatibility doctor that checks more than JSON Schema validity.

## Standards evidence for stable baseline matching

The [OASIS SARIF 2.1.0 standard](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) defines baseline states of `new`, `unchanged`, `updated`, and `absent`.

The standard also provides important matching guidance:

- Result systems should incorporate useful producer-supplied partial fingerprints.
- When two results share versions of a partial fingerprint algorithm, the latest common version should be used.
- Absolute line numbers should not be part of a stable fingerprint because inserting lines above a finding would incorrectly create a new identity.
- Stable matching is difficult in practice, and useful implementations should reduce false new results to a manageable level.

SARIF Lens should make these principles observable. The user should be able to see which signals were used, how paths were normalized, where candidates collided, and why the final pairing was selected.

## Why the product is review, diff, and gate

The word `viewer` describes an input format and a passive action. It does not describe the result a developer or security engineer needs.

`Review, diff, and gate` describes a complete job:

- Review explains the finding, rule, source location, code flow, related locations, fixes, suppressions, and raw SARIF fields.
- Diff separates new risk from existing debt and shows unchanged, updated, moved, resolved, and ambiguous findings.
- Gate turns the same interpretation into a deterministic merge or release decision.

The browser and CLI should be two interfaces to one core, not two separate implementations. If the browser reports three new high-severity findings, the CLI and CI gate must report the same three findings with the same identities and explanations.

A focused interface can use three primary modes:

1. Inspect
2. Compare
3. Policy

Report export, validation, compatibility checks, and raw inspection can support those modes without becoming separate products.

## Must-have product differentiators

### 1. Explainable, collision-safe matching

The matcher should:

- Prefer compatible final fingerprints when present.
- Treat partial fingerprints as version-aware evidence.
- Resolve rule references, URI base IDs, repository roots, path separators, and relative or absolute paths.
- Avoid absolute line number as primary identity.
- Use deterministic fallbacks based on tool, rule, normalized artifact, message template, source context, and optional Git rename or diff information.
- Enforce one-to-one pairings when fingerprints collide.
- Mark unresolved ambiguity rather than silently selecting a weak match.
- Expose evidence, confidence, competing candidates, and normalization steps through the UI and CLI.

Regression tests should cover inserted lines, renamed files, Windows and Linux root changes, duplicate fingerprints, fingerprint version changes, multiple runs, changed metadata, and equal-count new and resolved churn.

### 2. Tool-neutral policy gates

Policies should support:

- Baseline state.
- SARIF `level`.
- Security-severity score.
- Precision.
- Tool and rule.
- Tags and CWE metadata.
- Path globs.
- Suppression state.
- Match confidence or ambiguity.
- Zero-tolerance rules and numeric budgets.
- Reviewed exceptions with reason, owner, and expiry.

Generic SARIF level and security-specific severity should remain separate concepts. Policy files should be declarative YAML or JSON and must never execute arbitrary JavaScript.

### 3. Full-fidelity review

The workbench should render more than the first location and message. It should include rule help, related locations, `codeFlows`, `threadFlows`, fixes, suppressions, source snippets, tool and invocation metadata, and a JSON pointer view for interoperability debugging.

### 4. Real-world validation

Schema validation should be paired with precise warnings for common producer quirks. Inspection should be tolerant by default so users can understand imperfect files. Strict conformance can be an explicit policy requirement.

A compatibility doctor should check GitHub-specific version, property, URI, fingerprint, size, and count requirements. Any repair function should show a patch preview and never silently rewrite input.

### 5. Offline and hostile-input safety

SARIF content must be treated as untrusted. The application should sanitize Markdown, messages, snippets, and links, avoid automatic remote fetches, use a strict Content Security Policy, bound parsing and decompression, and ship without telemetry or external runtime assets.

The privacy statement should be precise: report data stays local. If the demo is hosted, explain that only the application shell is fetched. A downloadable build or cached progressive web app can make offline use concrete.

### 6. Performance as a contract

The browser should use worker-based parsing, virtualized result lists, indexed filtering, cancellation, and bounded memory. A useful benchmark target is GitHub's documented 25,000 results per run, plus multi-run files.

## Evidence-based launch principles

### Lead with the outcome

The README title and repository description should say what the project lets a user accomplish. The term SARIF can identify the ecosystem, but `viewer` should not be the main promise.

Recommended description:

> Offline SARIF workbench and CI gate. Inspect findings, compare baselines with explainable matching, and enforce tool-neutral policies.

### Demonstrate value before installation

A public demo should load a bundled baseline and current report immediately. The first screen should show a realistic case where line movement does not create a false new finding, while a same-count replacement is correctly identified as one resolved and one new result.

A short README animation should show:

1. Drop two files.
2. Inspect the delta.
3. Open a match explanation.
4. Apply a policy.
5. Run the same gate in CI.

### Minimize setup

The Node package should support direct use through `npx`. A compact command surface is sufficient:

```text
sarif-lens inspect results.sarif
sarif-lens diff baseline.sarif current.sarif
sarif-lens gate current.sarif --baseline baseline.sarif --policy .sarif-lens.yml
sarif-lens report current.sarif --baseline baseline.sarif -o report.html
sarif-lens doctor results.sarif --target github
sarif-lens explain-match baseline.sarif current.sarif --result <id>
```

### Close the CI loop

The [reviewdog](https://github.com/reviewdog/reviewdog) adoption signal shows the value of meeting developers where decisions happen. SARIF Lens should include a copy-paste GitHub Actions example and ideally a thin first-party action in the same repository. Job summaries, annotations, stable JSON output, and clear exit codes make the CLI useful beyond the browser.

### Use one shared engine

The browser, CLI, report generator, and action wrapper should all import the same TypeScript core. This is both an architecture principle and a trust promise. The project should publish fixtures proving identical counts and decisions across every interface.

### Ship interoperability evidence

Include generated or license-safe fixtures modeled after common outputs such as CodeQL, Semgrep, Trivy, ESLint, Bandit, and Ruff. Document what was tested, what is tolerated, and what remains unsupported.

### Make trust visible

Publish the policy schema, output schema, matching specification, threat model, performance benchmarks, and regression corpus. A security tool gains credibility when its decisions are reproducible and inspectable.

### Keep the project tool-neutral

Do not add scanning or rule authoring to this repository. Every scanner should be able to feed SARIF Lens. This keeps the open-source project independently useful while providing a natural integration point for VirtualSpace AppSec.

## Honest adoption assessment

SARIF Lens addresses a real gap, but it operates in a specialized ecosystem. Direct SARIF repositories show steady utility rather than automatic mass-market attention. A polished viewer alone would likely compete in the same narrow band.

The project has a stronger adoption case if it becomes the simplest way to answer three questions across any scanner:

1. What did this scan find?
2. What genuinely changed since the baseline?
3. Should this change pass policy?

Excellent execution, a live demo, deterministic matching, copy-paste CI, responsive maintenance, and clear documentation can improve the probability of stars and real use. None of those factors can guarantee stars, and the repository should never claim otherwise.
