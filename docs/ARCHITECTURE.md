# Architecture Overview

## Current Implementation Status

- Implemented: reusable workflow plus thin local wrapper workflow
- Implemented: local custom-rule scanning with Semgrep
- Implemented and live-validated: optional Semgrep Cloud backend selection through the reusable workflow
- Implemented: triage, deduplication, severity grouping, and PR comment rendering
- Implemented: first validated multi-language rule wave with 21 rules across Python, JavaScript/TypeScript, Go, and Java
- Implemented locally: optional AI domain context artifact for later enrichment phases
- Implemented and validated: optional AI finding enrichment step between triage and narrative
- Implemented: optional terrain synthesis step between triage and enrichment, validated locally, in Docker, and on the live CareTrack path
- Implemented: optional adversarial verification step between enrichment and narrative, validated locally, in Docker, with provider-backed smoke output, and on the live CareTrack path
- Implemented: optional cross-file taint tracing step between adversarial verification and narrative, validated locally, in Docker, with provider-backed smoke output, and on the live CareTrack path
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

`scanner/triage.py` normalizes severity, deduplicates results, sorts them by priority, preserves Semgrep `extra.lines` snippets when present, and prepares a structured JSON payload for reporting. It also carries forward the diff SHAs so later stages can reason about whether a finding was introduced in the PR or already existed in the touched file.

### Prompt Management Stage

AI prompt content lives in `prompts/*.toml` instead of being hardcoded in Python. `scanner/prompt_loader.py` loads and validates those files, applies a prompt-specific variable allowlist, sanitizes interpolated values, and caches parsed prompts for reuse within a job.

### Domain Context Stage

`scanner/domain_context.py` reads safe, top-level project metadata and writes `domain_context.json`. It builds provider prompts through the shared prompt loader instead of inline strings. The artifact is generated before scanning and cached when provider-backed generation succeeds. If no provider key is configured, no safe files exist, the prompt file is invalid, or the provider fails, it writes an unknown fallback context and the workflow continues.

### Terrain Stage

`scanner/terrain.py` reads `triaged-findings.json`, groups findings by file, reads the changed file content from the repository checkout, and asks the configured provider for file-local source and sink candidates. It then classifies each finding as `introduced`, `pre-existing`, or `unknown` by comparing the nearest source line with lines added in the PR diff. If no provider is available, it writes the triaged findings through unchanged. If a single file fails terrain synthesis, only that file's findings are marked `origin: unknown` and the rest continue.

### Enrichment Stage

`scanner/ai_enrich.py` reads `triaged-findings.json` or `terrain-findings.json`, optionally reads `domain_context.json`, and writes `enriched-findings.json`. It sends findings in a single batch prompt, validates that the model returns a JSON array, and only applies `enriched_finding`, `enriched_fix`, and `risk_context` fields that are actually present. Terrain fields pass through unchanged, and the prompt can reference taint context when available. If no matching provider key is configured, the prompt fails to load, the provider fails, or the response is malformed, it writes the original findings through unchanged and the workflow continues.

### Adversarial Verification Stage

`scanner/adversarial.py` reads `enriched-findings.json` or `terrain-findings.json`, optionally reads `domain_context.json`, and writes `verified-findings.json`. It makes one provider call per HIGH or CRITICAL finding, asks for the strongest evidence-based counter-argument, and applies only normalized `verdict`, `counter_argument`, and `adversarial_confidence` fields. LOW and MEDIUM findings pass through unchanged. If no matching provider key is configured, the prompt fails to load, a single provider call fails, or a response is malformed, the workflow leaves the affected findings unchanged and continues.

### Cross-File Taint Tracing Stage

`scanner/call_graph.py` reads `verified-findings.json`, optionally reads `domain_context.json`, and writes `call-graph-findings.json`. It builds a lightweight same-repo function index for Python and JavaScript/TypeScript, resolves outbound calls from changed functions, and asks the configured provider whether a downstream same-repo chain still appears to reach a dangerous sink. Matching chains are appended as low-confidence `origin: "cross-file"` observations. If no matching provider key is configured, a callee cannot be resolved, or a single provider call fails, the affected chain is skipped and the workflow continues.

### Narrative Stage

`scanner/narrative.py` reads `triaged-findings.json`, `enriched-findings.json`, `verified-findings.json`, or `call-graph-findings.json`, optionally generates a short PR-level risk narrative with Anthropic or OpenAI, and writes `narrative-findings.json`. The reusable workflow controls provider selection with `ai-provider` and model selection with `anthropic-model` and `openai-model`. Prompt content is loaded from `prompts/narrative.toml` through the shared loader. When verified or call-graph findings are present, the prompt includes the richer context automatically. If no matching provider key is configured, findings are empty, the prompt file is invalid, or the provider call fails, it writes `narrative: null` and the workflow continues normally.

### Comment Stage

`scanner/comment.py` renders the markdown findings table for the pull request, prefers enriched finding/fix text when present, includes the optional narrative blockquote when present, shows `NEW` / `PRE-EXISTING` badges when terrain data exists, appends inline adversarial notes for sustained findings, and can move challenged, pre-existing, or cross-file observations into collapsed sections while keeping the critical gate unchanged. It can also preview that output locally in dry-run mode.

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
7. Optional terrain synthesis is generated from triaged findings plus changed-file content.
8. Optional per-finding enrichment is generated from terrain-aware findings plus optional domain context.
9. Optional adversarial verification is generated from enriched findings plus optional domain context.
10. Optional cross-file taint tracing is generated from the verified findings plus same-repo call resolution.
11. An optional AI risk narrative is generated from the call-graph findings.
12. A markdown comment is rendered and posted to the pull request.
13. The workflow fails when a critical finding exists.
