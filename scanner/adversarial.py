#!/usr/bin/env python3
"""Optionally challenge HIGH and CRITICAL findings with per-finding adversarial review."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from scanner import ai_provider, prompt_loader


MAX_RESPONSE_TOKENS = 700
VERIFIABLE_SEVERITIES = {"high", "critical"}
select_provider = ai_provider.select_provider


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Enriched or terrain findings JSON path.")
    parser.add_argument("--output", required=True, help="Verified findings JSON path.")
    parser.add_argument(
        "--context",
        help="Optional domain context JSON path.",
    )
    return parser.parse_args()


def build_output_payload(payload: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    output = dict(payload)
    output["findings"] = findings
    return output


def build_system_prompt() -> str:
    return prompt_loader.render("adversarial", "system")


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


def one_line_text(value: Any) -> str:
    return " ".join(str(value).split())


def normalize_prompt_lines(value: Any) -> str:
    if value is None:
        return "unknown"
    text = str(value).strip()
    return text or "unknown"


def build_finding_block(finding: dict[str, Any]) -> str:
    prompt_payload = {
        "rule_id": str(finding.get("rule_id", "unknown-rule")),
        "severity": str(finding.get("severity", "unknown")),
        "file": str(finding.get("file", "")),
        "line": finding.get("line", ""),
        "finding": one_line_text(finding.get("finding", "")),
        "enriched_finding": one_line_text(finding.get("enriched_finding", "unknown")),
        "fix_suggestion": one_line_text(finding.get("fix_suggestion", "")),
        "enriched_fix": one_line_text(finding.get("enriched_fix", "unknown")),
        "risk_context": one_line_text(finding.get("risk_context", "unknown")),
        "cwe": one_line_text(finding.get("cwe", "N/A")),
        "lines": normalize_prompt_lines(finding.get("lines")),
        "origin": one_line_text(finding.get("origin", "unknown")),
        "taint_path": one_line_text(finding.get("taint_path", "unknown")),
        "source_description": one_line_text(finding.get("source_description", "unknown")),
        "sink_description": one_line_text(finding.get("sink_description", "unknown")),
    }
    return json.dumps(prompt_payload, indent=2)


def build_user_prompt(finding: dict[str, Any], domain_context: dict[str, Any] | None) -> str:
    return prompt_loader.render(
        "adversarial",
        "user_template",
        domain_summary=build_domain_summary(domain_context),
        finding_block=build_finding_block(finding),
    )


def parse_json_object(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end == -1 or end < start:
            raise
        parsed = json.loads(cleaned[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("Adversarial response must be a JSON object.")
    return parsed


def normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = one_line_text(value)
    if not cleaned or cleaned.lower() in {"unknown", "none", "null"}:
        return None
    return cleaned


def normalize_verdict(value: Any) -> str | None:
    cleaned = normalize_optional_text(value)
    if cleaned is None:
        return None
    normalized = cleaned.lower()
    if normalized in {"sustained", "downgraded"}:
        return normalized
    return None


def normalize_confidence(value: Any) -> str | None:
    cleaned = normalize_optional_text(value)
    if cleaned is None:
        return None
    normalized = cleaned.lower()
    if normalized in {"low", "medium", "high"}:
        return normalized
    return None


def normalize_verification_item(item: Any) -> dict[str, str]:
    if not isinstance(item, dict):
        raise ValueError("Adversarial response must be a JSON object.")

    verdict = normalize_verdict(item.get("verdict"))
    counter_argument = normalize_optional_text(item.get("counter_argument"))
    if verdict is None:
        raise ValueError("Adversarial response is missing a valid verdict.")
    if counter_argument is None:
        raise ValueError("Adversarial response is missing a valid counter_argument.")

    normalized = {
        "verdict": verdict,
        "counter_argument": counter_argument,
    }
    confidence = normalize_confidence(item.get("confidence"))
    if confidence is not None:
        normalized["adversarial_confidence"] = confidence
    return normalized


def should_verify(finding: dict[str, Any]) -> bool:
    severity = str(finding.get("severity", "")).strip().lower()
    return severity in VERIFIABLE_SEVERITIES


def generate_finding_verdict(
    finding: dict[str, Any],
    domain_context: dict[str, Any] | None,
    provider: dict[str, str],
) -> dict[str, str]:
    response = ai_provider.generate_text(
        build_system_prompt(),
        build_user_prompt(finding, domain_context),
        provider,
        max_tokens=MAX_RESPONSE_TOKENS,
    )
    return normalize_verification_item(parse_json_object(response))


def verify_payload(payload: dict[str, Any], domain_context: dict[str, Any] | None = None) -> dict[str, Any]:
    findings = [dict(finding) for finding in payload.get("findings", [])]
    if not findings:
        return build_output_payload(payload, findings)

    provider = select_provider()
    if provider is None:
        return build_output_payload(payload, findings)

    updated_findings: list[dict[str, Any]] = []
    for finding in findings:
        updated = dict(finding)
        if not should_verify(finding):
            updated_findings.append(updated)
            continue

        try:
            updated.update(generate_finding_verdict(finding, domain_context, provider))
        except Exception as exc:
            print(
                (
                    "Warning: adversarial verification failed "
                    f"({provider['name']} for {finding.get('file', '')}:{finding.get('line', '')}): {exc}"
                ),
                file=sys.stderr,
            )
        updated_findings.append(updated)

    return build_output_payload(payload, updated_findings)


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    domain_context = load_domain_context(args.context)
    output = verify_payload(payload, domain_context)
    Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
