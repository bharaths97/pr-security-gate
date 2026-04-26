# PR Security Gate

PR Security Gate is a GitHub Actions workflow that scans pull request changes with Semgrep, deduplicates and prioritizes findings, and posts the results back to the PR as a single markdown comment.

## What This Demonstrates

- Custom Semgrep rule authoring
- Pull-request scoped code scanning
- Security finding triage and severity normalization
- Developer-friendly PR reporting
- CI/CD enforcement on critical findings
- Secure workflow design choices around permissions and trust boundaries
- Modular delivery through a reusable GitHub workflow

## Project Docs

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Security Design](docs/SECURITY_DESIGN.md)
- [Client Integration Guide](docs/CLIENT_INTEGRATION.md)
- [AI Integration Roadmap](docs/AI_INTEGRATION.md)
- [Workflow Templates](docs/templates/README.md)
- [Assets Placeholder](docs/assets/README.md)

Private working notes are kept in a local gitignored `.internal/` directory and are intentionally not part of the hosted project documentation.

## Current Status

- Completed: reusable workflow model for multi-repo consumption
- Completed: local validation of 21 custom Semgrep rules across Python, JavaScript/TypeScript, Go, and Java
- Completed: local markdown preview for the PR comment body
- Completed: live end-to-end consumer-repo validation in both local and Semgrep Cloud modes
- Completed: optional AI risk narrative via Anthropic or OpenAI, validated locally and in GitHub Actions
- Completed: optional AI domain context artifact implemented and wired into the reusable workflow for later enrichment phases
- Completed: optional AI finding enrichment step now generates `enriched-findings.json`, feeds enriched text into the PR narrative, prefers enriched text in the comment table, and has been validated in GitHub Actions
- Implemented on `ai-phase4-terrain`: optional AI terrain synthesis now generates `terrain-findings.json`, classifies findings as `introduced` or `pre-existing`, adds taint-path context to the comment, and has passed local plus Docker unit validation
- Planned: pin Actions by SHA, add real PR evidence, and keep expanding the rule library beyond the current first wave

## Project Layout

```text
.github/workflows/pr-security-gate-reusable.yml
.github/workflows/security-scan.yml
docs/
rules/
scanner/ai_provider.py
scanner/ai_enrich.py
scanner/terrain.py
scanner/run_scan.py
scanner/triage.py
scanner/domain_context.py
scanner/narrative.py
scanner/comment.py
tests/vulnerable_samples/
requirements.txt
```

## How it works

1. The reusable workflow can be called from another repository through `workflow_call`, while this repo keeps a thin local wrapper workflow for self-demo use.
2. The reusable workflow checks out the caller repository to scan the PR code, then checks out this repo into a hidden subdirectory so it can reuse the shared scanner code and rules.
3. `scanner/run_scan.py` uses `git diff` between the PR base and head SHAs to identify changed files and supports two backends: local custom rules and Semgrep Cloud.
4. In `local` mode, Semgrep runs with the language-specific rule packs in [`rules/`](rules). In `cloud` mode, `semgrep ci` uses the repository's Semgrep AppSec Platform configuration.
5. `scanner/domain_context.py` optionally summarizes safe, top-level project metadata into `domain_context.json` for later AI phases.
6. `scanner/triage.py` deduplicates findings by `rule_id + file + line`, preserves Semgrep `extra.lines` snippets for later enrichment, sorts results from `critical` to `low`, and emits the structured finding summary.
7. `scanner/terrain.py` optionally analyzes each changed file with findings, identifies likely sources and sinks, and writes `terrain-findings.json` with `origin` and `taint_path` context when available.
8. `scanner/ai_enrich.py` optionally generates per-finding `enriched_finding`, `enriched_fix`, and `risk_context` fields from terrain-aware findings plus optional domain context.
9. `scanner/narrative.py` optionally adds a short AI risk narrative and writes `narrative-findings.json`. When enriched finding text exists, the narrative prompt uses that improved wording automatically.
10. `scanner/comment.py` can render the markdown comment locally in dry-run mode, prefers enriched text in the findings table when available, separates `pre-existing` findings into a collapsed section, and then uses `PyGithub` and `GITHUB_TOKEN` to upsert that same body to the pull request.
11. If any finding is `critical`, the comment step exits non-zero so the GitHub Action fails. With branch protection enabled for this check, the PR is blocked from merging.

## Modular Usage

This repo is now structured to act as the central source of truth for the scanner logic. Consumer repositories only need a tiny wrapper workflow that calls the reusable workflow in this repo.

Workflow roles:

- `pr-security-gate-reusable.yml`: the shared engine client repos should call
- `security-scan.yml`: this repo's self-test wrapper only
- client repos: their own tiny wrapper workflow that calls the shared engine remotely

Example consumer workflow:

```yaml
name: PR Security Gate

on:
  pull_request:
    types: [opened, synchronize]

permissions:
  contents: read
  pull-requests: write

jobs:
  pr-security-gate:
    uses: bharaths97/pr-security-gate/.github/workflows/pr-security-gate-reusable.yml@main
    with:
      security-gate-ref: main
      security-gate-repository: bharaths97/pr-security-gate
      scan-mode: local
    secrets:
      github-token: ${{ secrets.GITHUB_TOKEN }}
```

To opt into Semgrep Cloud mode, store `SEMGREP_APP_TOKEN` in the consumer repository or organization secrets and pass it through:

```yaml
jobs:
  pr-security-gate:
    uses: bharaths97/pr-security-gate/.github/workflows/pr-security-gate-reusable.yml@main
    with:
      security-gate-ref: main
      scan-mode: cloud
    secrets:
      github-token: ${{ secrets.GITHUB_TOKEN }}
      semgrep-app-token: ${{ secrets.SEMGREP_APP_TOKEN }}
```

Copy-ready wrapper examples live in [`docs/templates/`](docs/templates).

When testing a non-`main` branch of this repo, keep both refs aligned:

- the `uses: ...@branch-or-sha` ref selects which reusable workflow file GitHub loads
- `with.security-gate-ref` selects which branch or SHA this workflow checks out for the scanner code

If those two refs do not match, the workflow file and the Python scanner code can come from different revisions.

## Custom Rules Included

Current implemented rule coverage, validated locally:

- Python: 6 rules
- JavaScript / TypeScript: 5 rules
- Go: 5 rules
- Java: 5 rules

Total: 21 rules across 4 language packs.

Coverage themes in the current rule packs:

- Hardcoded secrets
- SQL injection patterns
- Missing authorization patterns
- Shell command execution with unsafe input
- Unsafe deserialization
- JWT verification misuse
- Open redirects
- TLS verification bypass
- Weak cryptography
- Trust-all SSL patterns

## Sample PR Comment Excerpt

Without AI narrative:

```markdown
## PR Security Gate Results

Status: failing because at least one critical finding was detected.

Scanned `21` changed source file(s) out of `21` changed file(s).
Findings: critical `4`, high `14`, medium `3`, low `0`.

| Severity | File | Line | Finding | CWE | Fix Suggestion |
| --- | --- | --- | --- | --- | --- |
| CRITICAL | `tests/vulnerable_samples/python/hardcoded_secret.py` | 1 | Hardcoded secret detected in source code. | CWE-798 | Move the secret to a secure secret manager or environment variable. |
| HIGH | `tests/vulnerable_samples/javascript/exec_user_input.js` | 4 | User-controlled input is passed into a shell command. | CWE-78 | Avoid shell execution with user input. Use argument arrays and validate input. |
| HIGH | `tests/vulnerable_samples/java/InsecureDeserialization.java` | 7 | ObjectInputStream.readObject can lead to insecure deserialization. | CWE-502 | Avoid Java native deserialization for untrusted data. |
| MEDIUM | `tests/vulnerable_samples/go/weak_md5.go` | 6 | MD5 is used in a security-sensitive context. | CWE-327 | Use a modern cryptographic primitive such as SHA-256 or a stronger password hashing function when appropriate. |

> Critical findings detected. This check fails so branch protection can block the merge until remediated.
```

With AI narrative (`ai-provider: auto` and a provider key configured):

```markdown
## PR Security Gate Results

> This PR introduces a hardcoded credential and an unsafe shell execution path. The critical secret exposure is the immediate remediation priority — it should be rotated and moved to a secret manager before merge. The command injection risk in the JavaScript helper is high severity and should also be addressed in this change.

Status: failing because at least one critical finding was detected.

Scanned `21` changed source file(s) out of `21` changed file(s).
Findings: critical `4`, high `14`, medium `3`, low `0`.
...
```

With AI enrichment plus narrative:

```markdown
## PR Security Gate Results

> This PR introduces a new shell execution path and also touches a pre-existing unsafe query path. The new command execution issue should be remediated before merge, while the older query path should be tracked explicitly because the PR did not introduce it.

Status: failing because at least one critical finding was detected.

Scanned `21` changed source file(s) out of `21` changed file(s).
Findings: critical `4`, high `14`, medium `3`, low `0`.

| Severity | File | Line | Finding | Taint Path | CWE | Fix Suggestion |
| --- | --- | --- | --- | --- | --- | --- |
| CRITICAL<br>NEW | `caretrack/support_tools.py` | 21 | User-controlled helper input reaches a shell execution path in the support tooling. | HTTP request parameter (line 10) -> subprocess.run(..., shell=True) (line 21) | CWE-78 | Validate the helper input, avoid shell execution, and pass arguments as an explicit list instead of invoking a shell. |
| HIGH<br>PRE-EXISTING | `caretrack/db.py` | 44 | A database query is still built from user-controlled input with string concatenation in legacy code touched by this PR. | User-controlled database parameter (line 30) -> cursor.execute(query) (line 44) | CWE-89 | Replace string-built queries with parameterized execution and keep untrusted values out of SQL text construction. |
...
```

## Local Preview

Run the full pipeline locally in Docker without posting to GitHub.

The empty tree SHA (`4b825dc...`) is used as the base so every file in HEAD appears as a new addition — this makes the vulnerable samples show up in the diff for local smoke testing regardless of when they were first committed:

```bash
docker compose run --rm security-gate \
  python scanner/domain_context.py --repo-root . --output domain_context.json

docker compose run --rm security-gate \
  python scanner/run_scan.py \
    --mode local \
    --rules rules \
    --base-sha 4b825dc642cb6eb9a060e54bf8d69288fbee4904 \
    --head-sha $(git rev-parse HEAD) \
    --output scan-results.json

docker compose run --rm security-gate \
  python scanner/triage.py --input scan-results.json --output triaged-findings.json

docker compose run --rm security-gate \
  python scanner/terrain.py \
    --input triaged-findings.json \
    --context domain_context.json \
    --output terrain-findings.json

docker compose run --rm security-gate \
  python scanner/ai_enrich.py \
    --input terrain-findings.json \
    --context domain_context.json \
    --output enriched-findings.json

docker compose run --rm security-gate \
  python scanner/narrative.py --input enriched-findings.json --output narrative-findings.json

docker compose run --rm security-gate \
  python scanner/comment.py --input narrative-findings.json --dry-run --output comment-preview.md
```

For AI smoke testing, copy `.env.ai.example` to `.env.ai`, add a provider key, and re-run the domain context, enrichment, or narrative step. Docker picks up `.env.ai` automatically via `compose.yaml`. If `.env.ai` is absent or contains no key, the AI steps still succeed with fallback output.

## Why This Is Useful

This project turns code scanning into something that is actually usable during review. Instead of flooding developers with full-repository findings, it focuses on the changed files in a pull request, summarizes the results cleanly, and gives reviewers a simple pass/fail signal when a critical issue appears.

That makes it useful for both security teams and developers:

- security teams get earlier detection in the development lifecycle
- developers get feedback in the PR where they are already working
- reviewers get findings that are easier to act on
- teams can turn the check into a merge gate with branch protection

## Roadmap

- Grow the current 21-rule baseline into a larger library with more obscure vulnerability checks
- Capture real PR screenshots from the consumer demo repo
- Pin third-party GitHub Actions by commit SHA

## Local Notes

- The workflow expects the default `GITHUB_TOKEN` provided by GitHub Actions.
- `actions/checkout` uses `fetch-depth: 0` so the PR base and head SHAs are available for `git diff`.
- The reusable workflow checks out both the caller repository and this central workflow repository so the scanner logic stays centralized.
- The sample files in [`tests/vulnerable_samples`](tests/vulnerable_samples) are intentionally insecure and exist to exercise the custom rules.
- A Docker-based local validation path is available via [`Dockerfile`](Dockerfile) and [`compose.yaml`](compose.yaml) to avoid host Python and Semgrep compatibility issues.
