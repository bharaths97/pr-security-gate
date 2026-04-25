#!/usr/bin/env python3
"""Generate an optional AI risk narrative from triaged findings."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from scanner import ai_provider, prompt_loader


MAX_PROMPT_FINDINGS = 25
DEFAULT_ANTHROPIC_MODEL = ai_provider.DEFAULT_ANTHROPIC_MODEL
DEFAULT_OPENAI_MODEL = ai_provider.DEFAULT_OPENAI_MODEL
select_provider = ai_provider.select_provider
extract_openai_text = ai_provider.extract_openai_text


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Triaged findings JSON path.")
    parser.add_argument("--output", required=True, help="Narrative findings JSON path.")
    return parser.parse_args()


def build_output_payload(payload: dict[str, Any], narrative: str | None) -> dict[str, Any]:
    output = dict(payload)
    output["narrative"] = narrative
    return output


def build_system_prompt() -> str:
    return prompt_loader.render("narrative", "system")


def build_findings_block(payload: dict[str, Any]) -> str:
    findings = payload.get("findings", [])
    prompt_findings = findings[:MAX_PROMPT_FINDINGS]
    lines = []

    for finding in prompt_findings:
        lines.append(
            "- {severity} | {file}:{line} | {message} | CWE: {cwe} | Suggested fix: {fix}".format(
                severity=str(finding.get("severity", "unknown")).upper(),
                file=finding.get("file", ""),
                line=finding.get("line", ""),
                message=one_line_text(finding.get("finding", "")),
                cwe=one_line_text(finding.get("cwe", "N/A")),
                fix=one_line_text(finding.get("fix_suggestion", "")),
            )
        )

    if len(findings) > len(prompt_findings):
        lines.append(
            f"- Additional findings omitted from prompt for brevity: {len(findings) - len(prompt_findings)}"
        )

    return "\n".join(lines)


def build_user_prompt(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    counts = summary.get("counts", {})
    source = payload.get("source", {})
    return prompt_loader.render(
        "narrative",
        "user_template",
        github_repository=os.getenv("GITHUB_REPOSITORY", "unknown"),
        pr_title=os.getenv("PR_TITLE", "unknown"),
        pr_branch=os.getenv("PR_BRANCH", "unknown"),
        critical=counts.get("critical", 0),
        high=counts.get("high", 0),
        medium=counts.get("medium", 0),
        low=counts.get("low", 0),
        scanned_files=len(source.get("scanned_files", [])),
        changed_files=len(source.get("changed_files", [])),
        findings_block=build_findings_block(payload),
    )


def one_line_text(value: Any) -> str:
    return " ".join(str(value).split())


def generate_narrative(payload: dict[str, Any], provider: dict[str, str]) -> str:
    text = ai_provider.generate_text(build_system_prompt(), build_user_prompt(payload), provider, max_tokens=220)

    cleaned = one_line_text(text)
    if not cleaned:
        raise RuntimeError("Provider returned an empty narrative.")
    return cleaned


def enrich_payload(payload: dict[str, Any]) -> dict[str, Any]:
    findings = payload.get("findings", [])
    if not findings:
        return build_output_payload(payload, None)

    provider = select_provider()
    if provider is None:
        return build_output_payload(payload, None)

    try:
        narrative = generate_narrative(payload, provider)
    except Exception as exc:
        print(f"Warning: narrative generation failed ({provider['name']}): {exc}", file=sys.stderr)
        narrative = None

    return build_output_payload(payload, narrative)


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    output = enrich_payload(payload)
    Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
