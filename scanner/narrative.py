#!/usr/bin/env python3
"""Generate an optional AI risk narrative from triaged or enriched findings."""

from __future__ import annotations

import argparse
import json
import os
import re
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
    parser.add_argument("--input", required=True, help="Triaged or enriched findings JSON path.")
    parser.add_argument("--output", required=True, help="Narrative findings JSON path.")
    parser.add_argument(
        "--context",
        help="Optional domain context JSON path.",
    )
    return parser.parse_args()


def build_output_payload(payload: dict[str, Any], narrative: str | None) -> dict[str, Any]:
    output = dict(payload)
    output["narrative"] = narrative
    return output


def build_system_prompt() -> str:
    return prompt_loader.render("narrative", "system")


def load_domain_context(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None

    context_path = Path(path)
    if not context_path.exists():
        return None

    try:
        loaded = json.loads(context_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Warning: unable to load domain context ({context_path}): {exc}", file=sys.stderr)
        return None

    return loaded if isinstance(loaded, dict) else None


def build_findings_block(payload: dict[str, Any]) -> str:
    findings = payload.get("findings", [])
    prompt_findings = findings[:MAX_PROMPT_FINDINGS]
    lines = []

    for finding in prompt_findings:
        lines.append(
            "- {severity} | {file}:{line} | {message} | CWE: {cwe} | Suggested fix: {fix}{adversarial}".format(
                severity=str(finding.get("severity", "unknown")).upper(),
                file=finding.get("file", ""),
                line=finding.get("line", ""),
                message=one_line_text(
                    finding.get("enriched_finding") or finding.get("finding") or finding.get("message", "")
                ),
                cwe=one_line_text(finding.get("cwe", "N/A")),
                fix=one_line_text(finding.get("enriched_fix") or finding.get("fix_suggestion", "")),
                adversarial=format_adversarial_context(finding),
            )
        )

    if len(findings) > len(prompt_findings):
        lines.append(
            f"- Additional findings omitted from prompt for brevity: {len(findings) - len(prompt_findings)}"
        )

    return "\n".join(lines)


def build_domain_summary(domain_context: dict[str, Any] | None) -> str:
    if not isinstance(domain_context, dict) or not domain_context.get("generated"):
        return "unknown"

    return "; ".join(
        [
            f"app_domain={one_line_text(domain_context.get('app_domain', 'unknown'))}",
            f"data_sensitivity={one_line_text(domain_context.get('data_sensitivity', 'unknown'))}",
            f"regulatory_context={join_values(domain_context.get('regulatory_context'))}",
            f"user_types={join_values(domain_context.get('user_types'))}",
            f"deployment={one_line_text(domain_context.get('deployment', 'unknown'))}",
            f"risk_tier={one_line_text(domain_context.get('risk_tier', 'unknown'))}",
        ]
    )


def join_values(value: Any) -> str:
    if not isinstance(value, list):
        return "unknown"
    cleaned = [one_line_text(item) for item in value if one_line_text(item)]
    return ", ".join(cleaned) if cleaned else "unknown"


def highest_severity_details(payload: dict[str, Any]) -> tuple[str, int, str]:
    summary = payload.get("summary", {})
    counts = summary.get("counts", {})
    findings = payload.get("findings", [])
    for severity in ("critical", "high", "medium", "low"):
        count = int(counts.get(severity, 0) or 0)
        if count > 0:
            for finding in findings:
                if one_line_text(finding.get("severity", "")).lower() == severity:
                    return severity.upper(), count, one_line_text(finding.get("file", "unknown"))
            return severity.upper(), count, "unknown"
    return "LOW", 0, "unknown"


def build_user_prompt(payload: dict[str, Any], domain_context: dict[str, Any] | None = None) -> str:
    summary = payload.get("summary", {})
    counts = summary.get("counts", {})
    source = payload.get("source", {})
    highest_severity, highest_severity_count, priority_file = highest_severity_details(payload)
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
        domain_summary=build_domain_summary(domain_context),
        highest_severity=highest_severity,
        highest_severity_count=highest_severity_count,
        priority_file=priority_file,
        scanned_files=len(source.get("scanned_files", [])),
        changed_files=len(source.get("changed_files", [])),
        findings_block=build_findings_block(payload),
    )


def one_line_text(value: Any) -> str:
    return " ".join(str(value).split())


def format_adversarial_context(finding: dict[str, Any]) -> str:
    verdict = one_line_text(finding.get("verdict", "")).lower()
    confidence = one_line_text(finding.get("adversarial_confidence", "")).lower()
    rationale = one_line_text(finding.get("rationale", ""))
    counter_argument = one_line_text(finding.get("counter_argument", ""))

    parts = []
    if verdict:
        parts.append(f"verdict={verdict}")
    if confidence:
        parts.append(f"confidence={confidence}")
    explanation = counter_argument if verdict == "downgraded" and counter_argument else rationale or counter_argument
    if explanation:
        label = "counter_argument" if verdict == "downgraded" and counter_argument else "rationale"
        parts.append(f"{label}={explanation}")
    if not parts:
        return ""
    return " | Adversarial review: " + "; ".join(parts)


def trim_to_one_sentence(text: str) -> str:
    cleaned = one_line_text(text)
    if not cleaned:
        return ""

    newline_trimmed = cleaned.split("\n", 1)[0].strip()
    match = re.match(r"^(.*?[.!?])(?:\s+|$)", newline_trimmed)
    if match:
        sentence = match.group(1).strip()
    else:
        sentence = newline_trimmed
    if sentence and sentence[-1] not in ".!?":
        sentence += "."
    return sentence


def build_domain_grounding_phrase(domain_context: dict[str, Any] | None) -> str:
    if not isinstance(domain_context, dict) or not domain_context.get("generated"):
        return ""
    app_domain = one_line_text(domain_context.get("app_domain", "application"))
    data_sensitivity = one_line_text(domain_context.get("data_sensitivity", "sensitive data"))
    return f"In a {app_domain} application handling {data_sensitivity}, "


def extract_next_step(text: str) -> str:
    sentence = trim_to_one_sentence(text)
    if not sentence:
        return "review the findings before merge."

    if " - " in sentence:
        candidate = sentence.split(" - ", 1)[1].strip()
    else:
        candidate = sentence

    candidate = candidate.strip()
    if candidate.lower().startswith("in a ") and "," in candidate:
        candidate = candidate.split(",", 1)[1].strip()
    count_match = re.match(
        r"^\d+\s+(critical|high|medium|low)\s+finding\(s\)\s+in\s+.+?\s+-\s+(.*)$",
        candidate,
        flags=re.IGNORECASE,
    )
    if count_match:
        candidate = count_match.group(2).strip()
    candidate = candidate.rstrip(".").strip()
    if not candidate:
        candidate = "review the findings before merge"
    return candidate + "."


def finalize_narrative(
    payload: dict[str, Any],
    text: str,
    domain_context: dict[str, Any] | None = None,
) -> str:
    highest_severity, highest_severity_count, priority_file = highest_severity_details(payload)
    prefix = f"{highest_severity_count} {highest_severity} finding(s) in {priority_file} - "
    domain_prefix = build_domain_grounding_phrase(domain_context)
    next_step = extract_next_step(text)
    final = f"{domain_prefix}{prefix}{next_step}"
    return trim_to_one_sentence(final)


def generate_narrative(
    payload: dict[str, Any],
    provider: dict[str, str],
    domain_context: dict[str, Any] | None = None,
) -> str:
    text = ai_provider.generate_text(
        build_system_prompt(),
        build_user_prompt(payload, domain_context),
        provider,
        max_tokens=220,
    )

    cleaned = one_line_text(text)
    if not cleaned:
        raise RuntimeError("Provider returned an empty narrative.")
    return finalize_narrative(payload, cleaned, domain_context)


def enrich_payload(payload: dict[str, Any], domain_context: dict[str, Any] | None = None) -> dict[str, Any]:
    findings = payload.get("findings", [])
    if not findings:
        return build_output_payload(payload, None)

    provider = select_provider()
    if provider is None:
        return build_output_payload(payload, None)

    try:
        narrative = generate_narrative(payload, provider, domain_context)
    except Exception as exc:
        print(f"Warning: narrative generation failed ({provider['name']}): {exc}", file=sys.stderr)
        narrative = None

    return build_output_payload(payload, narrative)


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    domain_context = load_domain_context(args.context)
    output = enrich_payload(payload, domain_context)
    Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
