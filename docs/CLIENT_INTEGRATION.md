# Client Integration Guide

This guide explains how downstream repositories should consume PR Security Gate.

## Workflow Roles

There are two workflow files in this repo, and they serve different purposes.

### Shared engine

File:

- `.github/workflows/pr-security-gate-reusable.yml`

Use:

- this is the workflow client repositories should call
- it contains the real scan, triage, and PR comment logic

### Self-test wrapper

File:

- `.github/workflows/security-scan.yml`

Use:

- this is only for running the gate on this repository itself
- it is not the template that client repositories should copy

## What Stays In This Repo

This repository owns:

- the reusable workflow
- the scanner scripts
- the Semgrep rules
- triage and comment rendering
- the local-vs-cloud backend abstraction

Client repositories should not copy scanner logic or rules into their own codebase.

## What Client Repositories Add

Each client repository adds one tiny wrapper workflow under:

- `.github/workflows/pr-security-gate.yml`

That wrapper should:

- trigger on `pull_request`
- call this repository's reusable workflow
- choose `scan-mode: local` or `scan-mode: cloud`
- optionally choose AI narrative settings with `ai-provider`, `anthropic-model`, and `openai-model`
- pass the required secrets

## Ref Alignment Rule

Client repositories need to understand two different refs when calling the shared workflow from another repository.

`uses: owner/repo/.github/workflows/file.yml@ref`

- tells GitHub which reusable workflow file to load

`with.security-gate-ref`

- tells the reusable workflow which revision of the PR Security Gate repository to `checkout` for scanner code and rules

For stable `main` usage, both can point to `main`.

When testing a feature branch, keep them aligned. Example:

```yaml
jobs:
  pr-security-gate:
    uses: bharaths97/pr-security-gate/.github/workflows/pr-security-gate-reusable.yml@semgrep-cloud-scan
    with:
      security-gate-ref: semgrep-cloud-scan
      scan-mode: cloud
```

If those values do not match, GitHub can load a new reusable workflow file while the job still checks out older scanner code from `main`.

## Local Mode Template

Use local mode when the client repo should run this repository's custom Semgrep rules only.

Reference file:

- [`docs/templates/client-pr-security-gate-local.yml`](templates/client-pr-security-gate-local.yml)

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
      scan-mode: local
      ai-provider: auto
    secrets:
      github-token: ${{ secrets.GITHUB_TOKEN }}
      anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
      openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

## Cloud Mode Template

Use cloud mode when the client repo is connected to Semgrep AppSec Platform and should run `semgrep ci`.

Reference file:

- [`docs/templates/client-pr-security-gate-cloud.yml`](templates/client-pr-security-gate-cloud.yml)

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
      scan-mode: cloud
      ai-provider: auto
    secrets:
      github-token: ${{ secrets.GITHUB_TOKEN }}
      semgrep-app-token: ${{ secrets.SEMGREP_APP_TOKEN }}
      anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
      openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

## Secret Ownership

`GITHUB_TOKEN`:

- comes from the client repository's GitHub Actions runtime

`SEMGREP_APP_TOKEN`:

- is stored in the client repository or organization secrets
- is only required for `scan-mode: cloud`

`ANTHROPIC_API_KEY` and `OPENAI_API_KEY`:

- are stored in the client repository or organization secrets
- are optional and only needed when the AI risk narrative should run
- if neither is passed, the workflow still posts the normal deterministic PR comment

This repository should not store client-specific Semgrep tokens.

## AI Narrative Options

The PR risk narrative is optional. By default, `ai-provider: auto` uses Anthropic when `anthropic-api-key` is passed, otherwise OpenAI when `openai-api-key` is passed. Set `ai-provider: none` to disable narrative generation explicitly.

Model inputs are optional:

- `anthropic-model`: defaults to `claude-sonnet-4-6`
- `openai-model`: defaults to `gpt-4o`

## Recommended Rollout

1. Start one client repo in `local` mode.
2. Verify scan, triage, comment, and merge-gate behavior.
3. Add `SEMGREP_APP_TOKEN` in the client repo or org.
4. Switch that client repo to `scan-mode: cloud`.
5. Add either `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` if the PR risk narrative should run.
6. Validate the hosted `semgrep ci` payload and PR comment behavior.

## CareTrack Example

CareTrack is the current demo consumer repo:

- `bharaths97/CareTrack`

Its wrapper workflow belongs at:

- `.github/workflows/pr-security-gate.yml`

Live validation result:

- CareTrack PR #3 was validated successfully in `cloud` mode using the thin-wrapper pattern
- the PR Security Gate comment posted successfully
- the run reported `2` high findings and `0` critical findings in the demo command-injection route
