#!/usr/bin/env python3
"""Optionally enrich findings with code-aware AI reviewer guidance."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from scanner import ai_provider, prompt_loader


MAX_PROMPT_FINDINGS = 25
MAX_RESPONSE_TOKENS = 1800
ENRICHMENT_FIELDS = ("enriched_finding", "enriched_fix", "risk_context")
select_provider = ai_provider.select_provider


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Triaged findings JSON path.")
    parser.add_argument("--output", required=True, help="Enriched findings JSON path.")
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
    return prompt_loader.render("enrich", "system")


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


def build_findings_block(findings: list[dict[str, Any]]) -> str:
    prompt_findings = findings[:MAX_PROMPT_FINDINGS]
    payload: dict[str, Any] = {
        "findings": [
            {
                "index": index,
                "rule_id": str(finding.get("rule_id", "unknown-rule")),
                "severity": str(finding.get("severity", "unknown")),
                "file": str(finding.get("file", "")),
                "line": finding.get("line", ""),
                "finding": one_line_text(finding.get("finding", "")),
                "fix_suggestion": one_line_text(finding.get("fix_suggestion", "")),
                "cwe": one_line_text(finding.get("cwe", "N/A")),
                "lines": normalize_prompt_lines(finding.get("lines")),
            }
            for index, finding in enumerate(prompt_findings)
        ]
    }
    if len(findings) > len(prompt_findings):
        payload["omitted_count"] = len(findings) - len(prompt_findings)
    return json.dumps(payload, indent=2)


def normalize_prompt_lines(value: Any) -> str:
    if value is None:
        return "unknown"
    text = str(value).strip()
    return text or "unknown"


def build_user_prompt(payload: dict[str, Any], domain_context: dict[str, Any] | None) -> str:
    return prompt_loader.render(
        "enrich",
        "user_template",
        domain_summary=build_domain_summary(domain_context),
        findings_block=build_findings_block(payload.get("findings", [])),
    )


def parse_json_array(text: str) -> list[Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start == -1 or end == -1 or end < start:
            raise
        parsed = json.loads(cleaned[start : end + 1])
    if not isinstance(parsed, list):
        raise ValueError("Enrichment response must be a JSON array.")
    return parsed


def normalize_enrichment_item(item: Any) -> dict[str, str]:
    if not isinstance(item, dict):
        return {}

    normalized: dict[str, str] = {}
    for field in ENRICHMENT_FIELDS:
        value = normalize_optional_text(item.get(field))
        if value is not None:
            normalized[field] = value
    return normalized


def normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = one_line_text(value)
    if not cleaned or cleaned.lower() in {"unknown", "none", "null"}:
        return None
    return cleaned


def one_line_text(value: Any) -> str:
    return " ".join(str(value).split())


def join_values(value: Any) -> str:
    if not isinstance(value, list):
        return "unknown"
    cleaned = [one_line_text(item) for item in value if one_line_text(item)]
    return ", ".join(cleaned) if cleaned else "unknown"


def generate_enrichments(
    payload: dict[str, Any],
    domain_context: dict[str, Any] | None,
    provider: dict[str, str],
) -> list[Any]:
    response = ai_provider.generate_text(
        build_system_prompt(),
        build_user_prompt(payload, domain_context),
        provider,
        max_tokens=MAX_RESPONSE_TOKENS,
    )
    return parse_json_array(response)


def apply_enrichments(findings: list[dict[str, Any]], enrichments: list[Any]) -> list[dict[str, Any]]:
    updated_findings: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        updated = dict(finding)
        if index < MAX_PROMPT_FINDINGS and index < len(enrichments):
            updated.update(normalize_enrichment_item(enrichments[index]))
        updated_findings.append(updated)
    return updated_findings


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


def enrich_payload(payload: dict[str, Any], domain_context: dict[str, Any] | None = None) -> dict[str, Any]:
    findings = [dict(finding) for finding in payload.get("findings", [])]
    if not findings:
        return build_output_payload(payload, findings)

    provider = select_provider()
    if provider is None:
        return build_output_payload(payload, findings)

    try:
        enrichments = generate_enrichments(payload, domain_context, provider)
        findings = apply_enrichments(findings, enrichments)
    except Exception as exc:
        print(f"Warning: enrichment generation failed ({provider['name']}): {exc}", file=sys.stderr)

    return build_output_payload(payload, findings)


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    domain_context = load_domain_context(args.context)
    output = enrich_payload(payload, domain_context)
    Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
