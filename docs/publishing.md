# Publishing handoff

This file records the intended public repository settings. It is not executed by the package.

## GitHub metadata

- Owner: `VirtualSpaceGit`
- Repository: `sarif-lens`
- Visibility: public
- Default branch: `main`
- Description: `Offline SARIF workbench and CI gate. Inspect findings, compare baselines with explainable matching, and enforce tool-neutral policies.`
- Homepage: `https://virtualspacegit.github.io/sarif-lens/`
- License: MIT
- Issues: enabled
- Discussions: enabled
- Wiki: disabled
- Projects: disabled initially

Topics:

```text
appsec
baseline
ci
code-scanning
developer-tools
devsecops
diff
javascript
nodejs
offline-first
sarif
sarif-report
sarif-viewer
sast
security-tools
static-analysis
```

## Suggested owner-run commands

Run these only after reviewing the local repository and authenticating the GitHub CLI to the intended account:

```bash
gh repo create VirtualSpaceGit/sarif-lens \
  --public \
  --description "Offline SARIF workbench and CI gate. Inspect findings, compare baselines with explainable matching, and enforce tool-neutral policies." \
  --homepage "https://virtualspacegit.github.io/sarif-lens/" \
  --source . \
  --remote origin \
  --push

gh repo edit VirtualSpaceGit/sarif-lens \
  --enable-issues \
  --enable-discussions \
  --enable-wiki=false \
  --enable-projects=false \
  --add-topic appsec,baseline,ci,code-scanning,developer-tools,devsecops,diff,javascript,nodejs,offline-first,sarif,sarif-report,sarif-viewer,sast,security-tools,static-analysis
```

Then configure Pages to use GitHub Actions if it is not selected automatically.

## Release checklist

1. Confirm `npm run check` passes from a clean clone.
2. Review the package contents with `npm pack --dry-run`.
3. Confirm the workbench and README links on Pages.
4. Push tag `v0.1.1` to trigger the release workflow.
5. Review the generated release notes and attached checksum.
6. Reserve and publish the `sarif-lens` npm name from the owner account if desired.
7. Add a short animated demo after capturing the live Pages build.
8. Announce the specific workflow result, not a generic product launch.

The npm package name and GitHub repository name appeared unclaimed when checked on 2026-08-11. That is an availability observation, not trademark clearance or a reservation.
