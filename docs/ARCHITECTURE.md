# Architecture Overview

## Current Implementation Status

- Implemented: reusable workflow plus thin local wrapper workflow
- Implemented: local custom-rule scanning with Semgrep
- Implemented: triage, deduplication, severity grouping, and PR comment rendering
- Implemented: first validated multi-language rule wave with 21 rules across Python, JavaScript/TypeScript, Go, and Java
- In progress: first live consumer-repo run
- Planned: deeper rule expansion and optional Semgrep Cloud support

## Components

### GitHub Workflow

`.github/workflows/pr-security-gate-reusable.yml` contains the shared workflow logic. `.github/workflows/security-scan.yml` is a thin local wrapper so this repo can still demonstrate the feature on itself.

### Scan Stage

`scanner/run_scan.py` determines which files changed in the PR and runs Semgrep only on supported source files from that diff.

### Triage Stage

`scanner/triage.py` normalizes severity, deduplicates results, sorts them by priority, and prepares a structured JSON payload for reporting.

### Comment Stage

`scanner/comment.py` renders a markdown table for the pull request and can also preview that output locally in dry-run mode.

### Detection Logic

`rules/` now contains multiple language-specific rule packs. The scan -> triage -> comment pipeline stays the same while rule coverage expands by adding new language packs and new vulnerable samples.

### Validation Samples

`tests/vulnerable_samples/` contains intentionally insecure files grouped by language so each custom rule has a matching vulnerable sample.

## Data Flow

1. Pull request event starts the workflow.
2. The caller repository is checked out for scanning, and the configured PR Security Gate repository is checked out for shared workflow assets.
3. Changed files are identified with `git diff`.
4. Semgrep scans the changed source files with the custom rules.
5. Findings are normalized and prioritized.
6. A markdown comment is rendered and posted to the pull request.
7. The workflow fails when a critical finding exists.
