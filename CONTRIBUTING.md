# Contributing

Thank you for helping make SARIF review more trustworthy and portable.

## Good first contributions

- Add a synthetic fixture for a real producer edge case
- Improve error messages for malformed SARIF
- Add a matching collision or path normalization test
- Improve keyboard or screen-reader behavior in the workbench
- Add documentation for a reproducible CI workflow

Never contribute a private scan report, customer path, credential, or proprietary source snippet. Reduce interoperability cases to synthetic data.

## Development setup

Requirements: Node 22 or newer.

```bash
git clone https://github.com/VirtualSpaceGit/sarif-lens.git
cd sarif-lens
npm install
npm run check
```

There are no runtime dependencies. Development should preserve that property unless a proposal demonstrates a clear security and maintenance benefit.

## Before opening a pull request

1. Add or update tests for behavior changes.
2. Run `npm run check`.
3. Keep output deterministic and stable.
4. Update the changelog for user-visible changes.
5. Document any change to identity, severity, or policy semantics.

Documentation uses direct language and ASCII punctuation. `npm run lint` checks the repository's text conventions.

## Matching changes

Matching behavior affects security gates. A pull request that changes result identity must include fixtures for:

- The intended match
- A nearby result that must not match
- Duplicate or ambiguous candidate behavior
- Line movement
- Stable ordering on repeated runs

Explain whether the change affects existing compact baselines.

## Web changes

SARIF fields are hostile text. Do not use report-derived `innerHTML`, fetch artifact URIs, add remote runtime assets, or persist scan contents in browser storage.

Test keyboard navigation and responsive behavior. Keep report processing in the Web Worker.

## Commit and pull request style

Use a short imperative subject, for example `Handle duplicate partial fingerprints`. Keep each pull request focused. Describe the user problem, evidence, solution, and tests.

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
