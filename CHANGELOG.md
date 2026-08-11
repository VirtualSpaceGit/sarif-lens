# Changelog

All notable changes are documented here. This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Tightened early-release and scanner-compatibility language
- Limited the npm package to user-facing documentation
- Updated GitHub workflows and examples to `actions/checkout@v7`
- Added an end-to-end check for the local GitHub Action metadata
- Removed unused npm caches from zero-dependency workflows

### Removed

- Internal research and stale publication notes
- Custom Pages workflow in favor of GitHub's branch publishing

## [0.1.1] - 2026-08-11

### Fixed

- Quick-start commands install directly from GitHub until the npm package is published
- Removed the hosted-workbench link until GitHub Pages is enabled

## [0.1.0] - 2026-08-11

### Added

- Offline browser workbench with baseline and current file loading
- Finding-level new, updated, fixed, and unchanged classification
- Explainable one-to-one matching with collision refusal
- Zero-runtime-dependency Node CLI
- Compact baseline snapshots
- Text, Markdown, JSON, CSV, and SARIF exports
- Versioned JSON policy gates and stable exit codes
- Composite GitHub Action with job summary and outputs
- Synthetic demo fixtures and automated tests
- Security, privacy, contribution, and matching documentation

[Unreleased]: https://github.com/VirtualSpaceGit/sarif-lens/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/VirtualSpaceGit/sarif-lens/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/VirtualSpaceGit/sarif-lens/releases/tag/v0.1.0
