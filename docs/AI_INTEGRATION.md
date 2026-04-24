# AI Integration Roadmap

This document describes the planned AI roadmap for PR Security Gate at a public-project level.

The current scanner, triage, comment, and merge-blocking workflow are already working without AI.
The AI roadmap extends that pipeline in stages so the project gains better reviewer guidance and deeper reasoning without destabilizing the existing gate.

## Current State

- The reusable workflow is working end to end
- The findings table and critical-failure gate are implemented
- AI augmentation is planned, but not yet implemented

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
