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
- Phase 4 terrain synthesis is implemented, validated in local, Docker, and CareTrack GitHub Actions runs, and wires a new terrain step between triage and enrichment
- Phase 5 adversarial verification is implemented on `ai-phase5-adversarial`, validated in local, Docker, provider-backed smoke, and CareTrack GitHub Actions runs, and wires a verifier step between enrichment and narrative
- Phase 6 cross-file taint tracing is implemented on `ai-phase6-cross-file`, validated in local, Docker, provider-backed smoke, and CareTrack GitHub Actions runs, and wires a call-graph step between adversarial verification and narrative
- Phase 7 PR threat model advisory is implemented, validated locally and in Docker, and wired into the reusable workflow as an opt-in step after terrain
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

`scanner/ai_enrich.py` reads `triaged-findings.json` or `terrain-findings.json`, optionally combines it with `domain_context.json`, and writes `enriched-findings.json`. Each finding may gain:

- `enriched_finding`
- `enriched_fix`
- `risk_context`

When enrichment succeeds, the PR comment table prefers `enriched_finding` and `enriched_fix` over the original Semgrep strings. The narrative step also reads from `enriched-findings.json`, so the PR-level summary can reflect the improved finding text automatically.

If no provider key is present, the provider call fails, the prompt fails to load, or the model returns malformed JSON, the workflow falls back to the original triaged finding text and continues normally. The critical gate still depends only on `summary.has_critical`.

Phase 3 reuses the same workflow inputs and secrets as Phases 1 and 2 — no new consumer-side configuration is required beyond optionally providing an AI provider key.

## Phase 4 Terrain Synthesis

`scanner/terrain.py` runs after triage and before enrichment. For each changed file that has findings, it sends the numbered file content and file-local finding summary to the configured provider, asks for likely taint sources and sinks, and writes `terrain-findings.json`.

When terrain succeeds, findings may gain:

- `origin` with `introduced`, `pre-existing`, or `unknown`
- `taint_path`
- `source_line`
- `sink_line`
- `source_description`
- `sink_description`

The PR comment can then surface a `NEW` or `PRE-EXISTING` badge in the severity column, add a `Taint Path` column when available, and move pre-existing findings into a collapsed `<details>` section. The critical gate is unchanged because it still depends only on structured severity counts.

If no provider key is present, `AI_PROVIDER=none` is used, the prompt fails to load, a file cannot be read, the provider fails, or the model returns malformed JSON for a file, the workflow degrades gracefully. No-provider mode writes the original triaged findings through unchanged. Per-file failures mark only that file's findings as `origin: unknown` and continue.

## Phase 5 Adversarial Verification

`scanner/adversarial.py` runs after enrichment and before narrative. It reads `enriched-findings.json`, optionally combines each HIGH or CRITICAL finding with `domain_context.json`, and writes `verified-findings.json`.

When verification succeeds, findings may gain:

- `verdict` with `sustained`, `downgraded`, or `insufficient_evidence`
- `rationale`
- `counter_argument` for `downgraded` findings only
- `adversarial_confidence`

The PR comment keeps sustained findings in the main table with an inline adversarial note, renders `insufficient_evidence` with a `? Uncertain` badge, moves downgraded non-critical findings into a collapsed `Challenged findings` section, and keeps CRITICAL findings in the main table so the deterministic critical gate is unchanged.

If no provider key is present, the prompt fails to load, the provider fails, or the model returns malformed JSON for one finding, the workflow degrades gracefully. No-provider mode writes the original enriched findings through unchanged. Per-finding failures leave only that finding without adversarial fields and continue.

## Phase 6 Cross-File Taint Tracing

`scanner/call_graph.py` runs after adversarial verification and before narrative. It reads `verified-findings.json`, indexes changed and same-repo Python or JavaScript/TypeScript functions, follows outbound calls up to `CALL_GRAPH_MAX_DEPTH`, and writes `call-graph-findings.json`.

When cross-file tracing succeeds, the output may gain appended low-confidence observations with:

- `origin: "cross-file"`
- `confidence: "low"`
- `chain`
- `hops`
- `sink_description`

These observations never change the deterministic gate. They render under a collapsed `Extended Analysis` section in the PR comment, while the main findings table and `summary.has_critical` behavior remain unchanged.

If no provider key is present, the prompt fails to load, a chain cannot be resolved, the provider fails, or one provider response is malformed, the workflow degrades gracefully. No-provider mode writes the original verified findings through unchanged. Per-chain failures skip only the affected chain and continue.

## Phase 7 PR Threat Model

`scanner/threat_model.py` is an optional advisory step that runs after terrain synthesis. It reads `domain_context.json`, `terrain-findings.json`, and `triage-findings.json`, takes the PR title and optional PR description as CLI arguments, and makes one AI call to generate a PR-scoped attack surface analysis.

The threat model is complementary to the security gate rather than a replacement for it. The security gate reasons per-finding — it tells you what code is broken. The threat model reasons per-PR — it tells you what became reachable and what an attacker could achieve with this diff.

When the threat model succeeds, `threat-model.json` contains:

- `blast_radius` — one sentence describing the worst realistic outcome
- `entry_points_added` — new touchpoints this PR exposed, with file and line
- `assets_at_risk` — data or systems an attacker could reach
- `threat_actors` — up to three actors who would realistically exploit this
- `mitigations_present` — existing defenses observed in the changed code
- `mitigations_absent` — expected defenses that are missing
- `domain_risks` — application-specific risks derived from `domain_context.json` (empty when domain is unknown)

The output is posted as a separate PR comment under `<!-- pr-threat-model -->`, distinct from the `<!-- pr-security-gate -->` security gate comment. This keeps the security gate results clean while giving the reviewer a separate advisory surface.

The step is opt-in via `run-threat-model: true` in the reusable workflow. It defaults to `false`. If no provider key is configured, a required input artifact is missing, or the AI call fails, the step writes `{"generated": false}` and exits 0. The threat model advisory never causes the workflow to fail.

PR description is treated as untrusted input. It is wrapped in nonce-tagged XML delimiters by `scanner/prompt_loader.py` before prompt substitution so it cannot override prompt instructions.

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
7. PR-level threat model advisory

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
| PR threat model | attack surface delta, blast radius, threat actors | terrain output + domain context + PR metadata |

## Design Principles

- AI should improve reviewer clarity without weakening the deterministic security gate
- AI failure should degrade gracefully, not break the pipeline
- The merge-blocking logic should remain grounded in structured findings, not model opinion
- Public documentation should stay outcome-focused until each phase is actually implemented and demonstrated
