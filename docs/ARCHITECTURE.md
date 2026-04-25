# Architecture Overview

## Current Implementation Status

- Implemented: reusable workflow plus thin local wrapper workflow
- Implemented: local custom-rule scanning with Semgrep
- Implemented and live-validated: optional Semgrep Cloud backend selection through the reusable workflow
- Implemented: triage, deduplication, severity grouping, and PR comment rendering
- Implemented: first validated multi-language rule wave with 21 rules across Python, JavaScript/TypeScript, Go, and Java
- Implemented locally: optional AI domain context artifact for later enrichment phases
- Implemented: live consumer-repo validation
- Implemented: local-vs-cloud tradeoff documentation
- Planned: deeper rule expansion

## Components

### GitHub Workflow

`.github/workflows/pr-security-gate-reusable.yml` contains the shared workflow logic and is the integration surface for downstream repositories.

`.github/workflows/security-scan.yml` is a thin local wrapper so this repo can still demonstrate and regression-test the feature on itself.

Client repositories are expected to add their own tiny wrapper workflow that points back to `pr-security-gate-reusable.yml`. Copyable examples live in `docs/templates/`.

### Scan Stage

`scanner/run_scan.py` determines which files changed in the PR and runs one of two backends:

- `local`: `semgrep scan` with the repository's custom rules
- `cloud`: `semgrep ci` with the repository's Semgrep AppSec Platform configuration

Both paths normalize their raw output into the same payload contract before triage.

### Triage Stage

`scanner/triage.py` normalizes severity, deduplicates results, sorts them by priority, preserves Semgrep `extra.lines` snippets when present, and prepares a structured JSON payload for reporting.

### Prompt Management Stage

AI prompt content lives in `prompts/*.toml` instead of being hardcoded in Python. `scanner/prompt_loader.py` loads and validates those files, applies a prompt-specific variable allowlist, sanitizes interpolated values, and caches parsed prompts for reuse within a job.

### Domain Context Stage

`scanner/domain_context.py` reads safe, top-level project metadata and writes `domain_context.json`. It builds provider prompts through the shared prompt loader instead of inline strings. The artifact is generated before scanning and cached when provider-backed generation succeeds. If no provider key is configured, no safe files exist, the prompt file is invalid, or the provider fails, it writes an unknown fallback context and the workflow continues.

### Narrative Stage

`scanner/narrative.py` reads `triaged-findings.json`, optionally generates a short PR-level risk narrative with Anthropic or OpenAI, and writes `narrative-findings.json`. The reusable workflow controls provider selection with `ai-provider` and model selection with `anthropic-model` and `openai-model`. Prompt content is loaded from `prompts/narrative.toml` through the shared loader. If no matching provider key is configured, findings are empty, the prompt file is invalid, or the provider call fails, it writes `narrative: null` and the workflow continues normally.

### Comment Stage

`scanner/comment.py` renders the markdown findings table for the pull request, includes the optional narrative blockquote when present, and can also preview that output locally in dry-run mode.

### Detection Logic

`rules/` now contains multiple language-specific rule packs. The scan -> triage -> comment pipeline stays the same while rule coverage expands by adding new language packs and new vulnerable samples.

### Validation Samples

`tests/vulnerable_samples/` contains intentionally insecure files grouped by language so each custom rule has a matching vulnerable sample.

## Data Flow

1. Pull request event starts the workflow.
2. The caller repository is checked out for scanning, and the configured PR Security Gate repository is checked out for shared workflow assets.
3. Changed files are identified with `git diff`.
4. Optional domain context is generated from safe project metadata.
5. The selected Semgrep backend runs against the pull request context.
6. Findings are normalized and prioritized.
7. An optional AI risk narrative is generated from the triaged findings.
8. A markdown comment is rendered and posted to the pull request.
9. The workflow fails when a critical finding exists.
