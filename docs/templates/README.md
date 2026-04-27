# Workflow Templates

These files are copyable thin-wrapper examples for client repositories.

## Files

- `client-pr-security-gate-local.yml`: wrapper for local custom-rule scanning
- `client-pr-security-gate-cloud.yml`: wrapper for Semgrep Cloud scanning

## How To Use

1. Copy the appropriate file into the client repository as:
   - `.github/workflows/pr-security-gate.yml`
2. Adjust both the `uses:` ref and `with.security-gate-ref` if you want to test a non-`main` branch.
3. For cloud mode, add `SEMGREP_APP_TOKEN` in the client repo or organization secrets.
4. For optional AI enrichment, add `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` and keep `ai-provider: auto`, or set `ai-provider: none` to disable AI.
5. When a provider key is present, domain context generation runs automatically before scanning and writes `domain_context.json` as a setup artifact for later AI phases. No additional configuration is needed — it reuses the same `ai-provider` and key inputs as the narrative step. If no key is present or the provider call fails, it writes a fallback context and the workflow continues normally.
6. To enable the optional PR-level threat model advisory, add `run-threat-model: true` to the `with:` block. This requires a provider key. When enabled, a separate advisory PR comment (`<!-- pr-threat-model -->`) is posted after the security gate comment. The advisory uses a blast-radius summary plus a compact STRIDE table for the most relevant categories supported by the PR artifacts. It defaults to `false` and can be omitted entirely if not needed.

The scanner logic stays centralized in this repository; client repos only need the thin wrapper.
