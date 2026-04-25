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
4. For the optional AI risk narrative, add `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` and keep `ai-provider: auto`, or set `ai-provider: none` to disable AI.

The scanner logic stays centralized in this repository; client repos only need the thin wrapper.
