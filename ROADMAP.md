# Roadmap

SARIF Lens follows user problems, interoperability evidence, and security impact. Dates are intentionally not promised.

## Next

- Add license-safe fixtures modeled on major SARIF producers
- Select the latest common version for versioned partial fingerprint families
- Resolve `originalUriBaseIds` safely
- Add Git rename-map input without invoking Git automatically
- Benchmark 25,000-result runs and publish memory and time results
- Add browser cancellation and clearer progress reporting
- Add strict opt-in SARIF schema conformance checks

## Later

- Standalone single-file offline workbench build
- Redacted standalone HTML review reports
- Policy selectors for tags, CWE, path, tool, and match confidence
- Reviewed exceptions keyed to stable finding identity
- Optional GitHub annotations from the Action
- Machined compatibility reports for scanner maintainers

## Non-goals

- Scanner execution
- Cloud accounts or report storage
- Vulnerability management workflows
- AI or opaque fuzzy matching
- Automatic suppression editing
- Artifact or source fetching

Open an issue with a concrete workflow and sample synthetic SARIF when proposing roadmap changes.

