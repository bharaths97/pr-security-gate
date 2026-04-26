# Security Design Notes

## Current Progress

- The reusable workflow design is implemented
- Local rule validation is implemented
- Semgrep Cloud support is implemented and validated on a live consumer PR
- The first multi-language expansion wave is implemented and validated locally
- The live consumer-repo proof step is complete
- Expanded cross-language rule depth is still a roadmap item beyond the current 21-rule baseline

## Goals

This project is designed to show both application security scanning and CI/CD security judgment. The goal is not just to run a scanner, but to integrate it into pull request workflows in a way that developers can trust and reviewers can act on.

## Key Design Choices

### Scan Only Changed Files

`scanner/run_scan.py` scopes the pull request context by using `git diff` between the PR base and head SHAs. It uses a two-commit diff (`base..head`) rather than a three-dot merge-base diff (`base...head`) — the two-dot form does a direct comparison between any two git objects, which works correctly with real PR SHAs in CI and also supports the empty tree SHA used for local smoke testing. In local mode, it scans only matching changed source files with the repository's custom Semgrep rules. In cloud mode, it runs `semgrep ci` with the repository's Semgrep AppSec Platform configuration while preserving the same downstream triage contract.

This keeps results focused on the pull request instead of turning the workflow into a noisy full-repository dump.

### Explicit Backend Selection

The reusable workflow uses an explicit `scan-mode` input instead of auto-detecting the backend.

- `local` remains the default
- `cloud` requires `SEMGREP_APP_TOKEN`
- cloud mode does not silently fall back to local mode

This keeps the workflow behavior predictable during rollout, demos, and debugging.

### Local Vs Cloud Tradeoff

Local mode is self-contained and easy to demo because it uses the custom rules in this repository and scans only changed source files. Its coverage is limited by the local rule library.

Cloud mode uses Semgrep AppSec Platform through `semgrep ci`, so it can apply broader managed rules and repository policy. It requires `SEMGREP_APP_TOKEN` and runs with Semgrep Cloud's repository-aware behavior, which is why the PR comment describes cloud scope separately from local changed-file scope.

### Fail Only on Critical Findings

The workflow posts all findings to the pull request, but it only fails the check when a finding is marked `critical`. This creates a practical balance between visibility and enforcement.

### Minimal GitHub Token Permissions

The workflow requests only:

- `contents: read`
- `pull-requests: write`

That permission model is enough to read the repository contents and write the PR comment without over-granting workflow access.

### Domain Context Trust Boundary

`scanner/domain_context.py` reads only a narrow allowlist of safe, top-level project metadata files — README, Dockerfile, dependency manifests, and example or sample configs. It explicitly denies `.env`, local environment variants such as `.env.production`, all source code, and nested directories such as `.git`, `.pr-*`, virtual environments, and dependency folders. It also denies generated workflow artifacts by pattern, including files such as `*-findings.json`, `*-results.json`, `*_context.json`, and `*-preview.md`, to prevent feedback loops. A `MAX_CONTEXT_BYTES` cap limits how much content is sent to the provider. If no safe files exist, no provider key is present, or the provider call fails, it writes a structured fallback context and the workflow continues — the scan, triage, comment, and critical gate steps are unaffected.

### Developer-Friendly Output

The project does not dump raw Semgrep JSON onto the pull request. Instead, it:

- deduplicates results
- normalizes severity
- adds CWE references
- adds fix suggestions
- renders a readable markdown table

### AI Context Boundaries

The domain context step reads only safe, top-level project metadata such as README, Docker, dependency, and example config files. It does not read `.env`, source files, dependency folders, or the checked-out scanner repository. If AI is unavailable or fails, it writes an unknown fallback context and does not affect the deterministic security gate.

AI prompt text is centralized under `prompts/*.toml` and rendered through `scanner/prompt_loader.py`. The loader enforces a prompt-specific variable allowlist, strips control characters from interpolated values, replaces `None` with `unknown`, and caps injected value size before provider submission. Narrative and future enrichment prompts also include an explicit instruction that user-controlled findings text must be treated as data, not as instructions.

The terrain step sends the full content of changed files that already contain findings, along with diff metadata needed to distinguish new versus pre-existing sources. The enrichment step sends flagged code snippets from Semgrep's `extra.lines` field plus any terrain context so the generated finding and remediation text can reference the actual code under review. Those are deliberate trust-boundary choices: the model sees changed-file content and snippets, but its output only affects reviewer-facing text in the PR comment and narrative.

This does not eliminate prompt injection risk entirely because finding data, changed file content, and repository metadata can still contain adversarial strings, but it keeps that input visible, bounded, and separate from merge-blocking logic. AI output still only affects reviewer-facing text, terrain labeling, and commentary structure, while the critical gate remains driven by deterministic triage data.

### Local Reproducibility

The Docker path exists to avoid host Python and Semgrep compatibility issues. It gives the project a repeatable Python 3.11 environment for local rule validation and demo preparation.

### Centralized Reuse

The project is structured as a reusable workflow so the scanner logic can stay centralized in one repository instead of being copied into every consumer repository. Downstream repositories only need a small wrapper workflow that calls the shared workflow.

### Explicit Consumer Contract

The consumer contract is intentionally split into:

- a shared engine in `.github/workflows/pr-security-gate-reusable.yml`
- a self-test wrapper in `.github/workflows/security-scan.yml`
- a tiny wrapper workflow in each client repository

That separation matters because distribution is part of the design, not just the docs. Client repositories should only own their trigger file and their environment-specific secrets. The scanner logic, triage behavior, and comment rendering remain centralized here.

### Secret Ownership

Client-specific secrets stay with the client repository or organization.

- `GITHUB_TOKEN` comes from the client repo's GitHub Actions runtime
- `SEMGREP_APP_TOKEN` belongs in the client repo or org secrets when cloud mode is enabled

This repository should not own or store downstream Semgrep Cloud tokens.

## Trust Boundary Notes

This project uses the `pull_request` event, not `pull_request_target`, because the latter changes the trust boundary and can be dangerous when running on untrusted fork content. For a showcase project, this is an important design choice to explain clearly.

## Future Hardening

- Pin GitHub Actions by commit SHA
- Expand beyond the current 21 local custom rules and include more obscure vulnerability patterns
- Add screenshots from a real PR run
