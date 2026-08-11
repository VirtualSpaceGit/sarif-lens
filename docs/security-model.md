# Security model

SARIF reports can contain private source paths, snippets, vulnerability details, URLs, and attacker-controlled strings. SARIF Lens treats every report as hostile input.

## Browser boundary

- Parsing and comparison run in a Web Worker.
- The hosted workbench makes no report upload request.
- `connect-src 'none'` blocks script-initiated network connections.
- No remote script, stylesheet, font, or image is required at runtime.
- Report data is not written to `localStorage` or IndexedDB.
- Artifact URIs are shown as text and are not fetched or opened automatically.
- UI content is created with DOM nodes and `textContent`, not report-derived HTML.
- The browser rejects files larger than 50 MiB before parsing.

The page application itself must be fetched from its host. For a disconnected workflow, serve a cloned copy locally.

## CLI boundary

- Input files larger than 100 MiB are rejected.
- Policy is declarative JSON. No dynamic code is loaded from it.
- Output files are written only when the user provides an output path.
- The CLI has zero runtime package dependencies.

The CLI reads complete JSON input into memory. It does not yet implement streaming JSON parsing, nesting-depth limits, or a wall-clock parsing timeout. Use operating-system resource limits for untrusted batch processing where denial of service is a concern.

## Export safety

- Markdown delimiters and table cells are escaped.
- Terminal escape sequences and unsafe control or bidirectional characters are removed or rendered visibly in human-readable output.
- CSV cells beginning with `=`, `+`, `-`, or `@` are prefixed so spreadsheet software does not interpret them as formulas.
- SARIF and JSON exports are generated through `JSON.stringify`.
- Browser downloads use object URLs that are revoked after the click.

## Trust assumptions

Producer fingerprints are evidence, not proof. A producer can emit collisions, unstable paths, misleading severities, or incorrect source locations. SARIF Lens reports its match strategy and refuses ambiguous one-to-many result matches, but reviewers remain responsible for trusting the scanner.

The Content Security Policy is defense in depth. A browser extension or compromised local machine is outside this project's boundary.

## Reporting

See [SECURITY.md](../SECURITY.md) for supported versions and private reporting instructions.
