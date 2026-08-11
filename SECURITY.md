# Security policy

SARIF Lens processes security scan reports that may contain private paths, source snippets, and vulnerability details. Please report vulnerabilities privately.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | Best effort |

## Report a vulnerability

Email `support@virtualspacesec.com` with:

- A concise description of the issue
- Affected version and interface, such as browser, CLI, library, or Action
- Reproduction steps or a minimal synthetic SARIF file
- Security impact
- Any suggested fix

Do not include private customer reports, production credentials, or proprietary source code. Create the smallest synthetic fixture that demonstrates the issue.

You can expect an acknowledgement within three business days. We will coordinate remediation and disclosure timing with the reporter.

## Relevant threat areas

Reports are especially useful for:

- Script or markup injection through SARIF fields
- Unexpected browser network requests
- Artifact URI fetching or unsafe navigation
- CSV formula injection
- Path traversal during output generation
- Resource exhaustion with malformed JSON or deeply nested fields
- Incorrect policy pass or fail behavior
- Ambiguous result matches that are silently accepted

See [the security model](docs/security-model.md) for current boundaries and known limits.

