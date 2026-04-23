# Security Design Notes

## Current Progress

- The reusable workflow design is implemented
- Local rule validation is implemented
- The first multi-language expansion wave is implemented and validated locally
- The live consumer-repo proof step is still pending
- Expanded cross-language rule depth is still a roadmap item beyond the current 21-rule baseline

## Goals

This project is designed to show both application security scanning and CI/CD security judgment. The goal is not just to run a scanner, but to integrate it into pull request workflows in a way that developers can trust and reviewers can act on.

## Key Design Choices

### Scan Only Changed Files

`scanner/run_scan.py` scopes Semgrep to the files changed in the pull request by using `git diff` between the PR base and head SHAs. This keeps results relevant to the code under review and reduces the noise that often causes security tooling to be ignored.

### Fail Only on Critical Findings

The workflow posts all findings to the pull request, but it only fails the check when a finding is marked `critical`. This creates a practical balance between visibility and enforcement.

### Minimal GitHub Token Permissions

The workflow requests only:

- `contents: read`
- `pull-requests: write`

That permission model is enough to read the repository contents and write the PR comment without over-granting workflow access.

### Developer-Friendly Output

The project does not dump raw Semgrep JSON onto the pull request. Instead, it:

- deduplicates results
- normalizes severity
- adds CWE references
- adds fix suggestions
- renders a readable markdown table

### Local Reproducibility

The Docker path exists to avoid host Python and Semgrep compatibility issues. It gives the project a repeatable Python 3.11 environment for local rule validation and demo preparation.

### Centralized Reuse

The project is structured as a reusable workflow so the scanner logic can stay centralized in one repository instead of being copied into every consumer repository. Downstream repositories only need a small wrapper workflow that calls the shared workflow.

## Trust Boundary Notes

This project uses the `pull_request` event, not `pull_request_target`, because the latter changes the trust boundary and can be dangerous when running on untrusted fork content. For a showcase project, this is an important design choice to explain clearly.

## Future Hardening

- Pin GitHub Actions by commit SHA
- Add explicit automated rule tests
- Expand beyond the current 21 local custom rules and include more obscure vulnerability patterns
- Add Semgrep Cloud as an optional backend alongside local custom rules
- Add screenshots from a real PR run
