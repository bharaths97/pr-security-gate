# AI Integration Roadmap

This document describes the planned AI roadmap for PR Security Gate at a public-project level.

The current scanner, triage, comment, and merge-blocking workflow are already working without AI.
The AI roadmap extends that pipeline in stages so the project gains better reviewer guidance and deeper reasoning without destabilizing the existing gate.

## Current State

- The reusable workflow is working end to end
- The findings table and critical-failure gate are implemented
- Phase 1 risk narrative is implemented and validated as an optional enrichment step
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
| `openai-model` | `gpt-4o` | Model used when OpenAI is selected. |

Provider keys are passed as optional workflow secrets: `anthropic-api-key` and `openai-api-key`.

For local Docker smoke testing, copy `.env.ai.example` to `.env.ai` and set the same environment variables used by `scanner/narrative.py`. The `.env.ai` file is ignored by Git and is only for local validation.

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
| Fix suggestions | code-specific remediation guidance | best with domain context |
| Terrain synthesis | source-to-sink reasoning in changed files | changed-file scan data |
| Adversarial verification | challenge and validate finding quality | best with terrain output |
| Cross-file reasoning | broader multi-file context | optional later enhancement |

## Design Principles

- AI should improve reviewer clarity without weakening the deterministic security gate
- AI failure should degrade gracefully, not break the pipeline
- The merge-blocking logic should remain grounded in structured findings, not model opinion
- Public documentation should stay outcome-focused until each phase is actually implemented and demonstrated
