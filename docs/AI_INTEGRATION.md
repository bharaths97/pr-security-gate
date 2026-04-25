# AI Integration Roadmap

This document describes the planned AI roadmap for PR Security Gate at a public-project level.

The current scanner, triage, comment, and merge-blocking workflow are already working without AI.
The AI roadmap extends that pipeline in stages so the project gains better reviewer guidance and deeper reasoning without destabilizing the existing gate.

## Current State

- The reusable workflow is working end to end
- The findings table and critical-failure gate are implemented
- Phase 1 risk narrative is implemented and validated as an optional enrichment step
- Phase 2 domain context is implemented locally as a setup artifact for later AI phases
- Phase 3 finding enrichment is implemented and validated in the reusable workflow between triage and narrative
- AI prompts are centralized under `prompts/*.toml` and rendered through a shared allowlist-based loader
- If no AI provider key is present or a provider call fails, the workflow falls back to the normal comment without weakening the gate

## Phase 1 Output

When a provider key is configured, the narrative appears as a blockquote above the findings table in the PR comment:

```
> This PR introduces a hardcoded credential and an unsafe shell execution path.
> The critical secret exposure is the immediate remediation priority — it should
> be rotated and moved to a secret manager before merge. The command injection
> risk in the helper script is high severity and should also be addressed here.
```

If no provider key is present, the provider call fails, or findings are empty, the blockquote is omitted and the rest of the comment renders normally. The merge-blocking gate is unaffected in either case.

## Phase 1 Configuration

The reusable workflow exposes explicit AI controls for the PR risk narrative:

| Input | Default | Behavior |
| --- | --- | --- |
| `ai-provider` | `auto` | Uses Anthropic when `anthropic-api-key` is present, otherwise OpenAI when `openai-api-key` is present. Use `anthropic`, `openai`, or `none` to force a choice. |
| `anthropic-model` | `claude-sonnet-4-6` | Model used when Anthropic is selected. |
| `openai-model` | `gpt-4o-mini` | Model used when OpenAI is selected. |

Provider keys are passed as optional workflow secrets: `anthropic-api-key` and `openai-api-key`.

For local Docker smoke testing, copy `.env.ai.example` to `.env.ai` and set the same environment variables used by `scanner/narrative.py`. The `.env.ai` file is ignored by Git and is only for local validation.

## Phase 2 Domain Context

`scanner/domain_context.py` reads safe, top-level project metadata such as README, Docker, dependency, and example config files. It writes `domain_context.json` for later AI phases.

If a provider key is available, the file contains a compact summary of application domain, data sensitivity, user types, deployment, and risk tier. If AI is unavailable or fails, it still writes an unknown fallback context and the workflow continues normally.

Phase 2 does not change the PR comment or merge-blocking behavior yet. It prepares context for later fix-suggestion, terrain, and verification phases.

Phase 2 reuses the same provider inputs as Phase 1 — no new workflow configuration is required. The same `ai-provider`, `anthropic-api-key`, `openai-api-key`, and model inputs control both steps.

## Phase 3 Finding Enrichment

`scanner/ai_enrich.py` reads `triaged-findings.json`, optionally combines it with `domain_context.json`, and writes `enriched-findings.json`. Each finding may gain:

- `enriched_finding`
- `enriched_fix`
- `risk_context`

When enrichment succeeds, the PR comment table prefers `enriched_finding` and `enriched_fix` over the original Semgrep strings. The narrative step also reads from `enriched-findings.json`, so the PR-level summary can reflect the improved finding text automatically.

If no provider key is present, the provider call fails, the prompt fails to load, or the model returns malformed JSON, the workflow falls back to the original triaged finding text and continues normally. The critical gate still depends only on `summary.has_critical`.

Phase 3 reuses the same workflow inputs and secrets as Phases 1 and 2 — no new consumer-side configuration is required beyond optionally providing an AI provider key.

## Prompt Management

Prompt text is versioned separately from Python logic under `prompts/*.toml`. `scanner/prompt_loader.py` validates prompt structure, caches parsed TOML, enforces a per-prompt variable allowlist, strips control characters from injected values, and caps interpolation size before provider calls are made.

That keeps prompt changes visible in isolated diffs and narrows the blast radius of prompt-injection attempts carried through finding text or repository metadata. If a prompt file is missing or malformed, the AI step falls back the same way it would on provider failure and the workflow still continues.

## Planned Rollout

1. PR-level risk narrative
2. Domain context
3. Contextualized fix suggestions
4. Terrain synthesis
5. Adversarial verification
6. Optional cross-file reasoning

## Why This Order

The first AI phase is designed to ship quickly and visibly by adding a short risk narrative to the PR comment.
Later phases build deeper contextual reasoning and better prioritization, but they require more structured context and more pipeline coordination.

## Dependency View

| Phase | Purpose | Depends on |
| --- | --- | --- |
| Risk narrative | PR-level summary for reviewers | current triage output |
| Domain context | app/domain understanding | none |
| Fix suggestions | code-specific remediation guidance | triage `lines`, best with domain context |
| Terrain synthesis | source-to-sink reasoning in changed files | changed-file scan data |
| Adversarial verification | challenge and validate finding quality | best with terrain output |
| Cross-file reasoning | broader multi-file context | optional later enhancement |

## Design Principles

- AI should improve reviewer clarity without weakening the deterministic security gate
- AI failure should degrade gracefully, not break the pipeline
- The merge-blocking logic should remain grounded in structured findings, not model opinion
- Public documentation should stay outcome-focused until each phase is actually implemented and demonstrated
