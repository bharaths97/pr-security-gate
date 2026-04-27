#!/usr/bin/env python3
"""Optionally generate a PR-level threat model advisory from existing pipeline artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from scanner import ai_provider, prompt_loader


MAX_RESPONSE_TOKENS = 500
MAX_CHANGED_FILES = 50
MAX_ENTRY_POINTS = 20
MAX_SINKS = 20
MAX_PRIORITY_FINDINGS = 10
select_provider = ai_provider.select_provider


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain-context", required=True, help="Domain context JSON path.")
    parser.add_argument("--terrain", required=True, help="Terrain findings JSON path.")
    parser.add_argument("--triage", required=True, help="Triaged findings JSON path.")
    parser.add_argument("--pr-title", required=True, help="Pull request title.")
    parser.add_argument("--pr-description", help="Optional pull request description.")
    parser.add_argument("--output", required=True, help="Threat model JSON path.")
    return parser.parse_args()


def build_fallback_output() -> dict[str, bool]:
    return {"generated": False}


def build_system_prompt() -> str:
    return prompt_loader.render("threat_model", "system")


def load_json_object(path: str, label: str) -> dict[str, Any] | None:
    artifact_path = Path(path)
    if not artifact_path.exists():
        print(f"Warning: missing {label} artifact ({artifact_path})", file=sys.stderr)
        return None

    try:
        loaded = json.loads(artifact_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Warning: unable to load {label} artifact ({artifact_path}): {exc}", file=sys.stderr)
        return None

    if not isinstance(loaded, dict):
        print(f"Warning: {label} artifact must be a JSON object ({artifact_path})", file=sys.stderr)
        return None
    return loaded


def one_line_text(value: Any) -> str:
    return " ".join(str(value).split())


def join_values(value: Any) -> str:
    if not isinstance(value, list):
        return "unknown"
    cleaned = [one_line_text(item) for item in value if one_line_text(item)]
    return ", ".join(cleaned) if cleaned else "unknown"


def build_domain_summary(domain_context: dict[str, Any]) -> str:
    if not domain_context.get("generated"):
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


def build_pr_description_section(pr_description: str | None) -> str:
    description = one_line_text(pr_description or "")
    if not description:
        return ""
    return f"PR description:\n{description}"


def build_changed_files_block(terrain_payload: dict[str, Any]) -> str:
    source = terrain_payload.get("source", {})
    changed_files = source.get("changed_files", []) or source.get("scanned_files", [])
    if not isinstance(changed_files, list):
        changed_files = []

    cleaned = sorted(
        {
            one_line_text(item)
            for item in changed_files
            if one_line_text(item)
        }
    )
    payload: dict[str, Any] = {"changed_files": cleaned[:MAX_CHANGED_FILES]}
    if len(cleaned) > MAX_CHANGED_FILES:
        payload["omitted_count"] = len(cleaned) - MAX_CHANGED_FILES
    return json.dumps(payload, indent=2)


def normalize_positive_int(value: Any) -> int | None:
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
        if parsed > 0:
            return parsed
    return None


def collect_entry_points(terrain_payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings = terrain_payload.get("findings", [])
    if not isinstance(findings, list):
        return []

    entry_points: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        origin = one_line_text(finding.get("origin", "")).lower()
        file_path = one_line_text(finding.get("file", ""))
        source_description = one_line_text(finding.get("source_description", ""))
        source_line = normalize_positive_int(finding.get("source_line"))
        if origin not in {"introduced", "new"}:
            continue
        if not file_path or source_line is None or not source_description:
            continue
        item = (file_path, source_line, source_description)
        if item in seen:
            continue
        seen.add(item)
        entry_points.append(
            {"file": file_path, "line": source_line, "description": source_description}
        )

    return sorted(entry_points, key=lambda item: (item["file"], item["line"], item["description"]))


def build_entry_points_block(terrain_payload: dict[str, Any]) -> str:
    entry_points = collect_entry_points(terrain_payload)
    payload: dict[str, Any] = {"entry_points_added": entry_points[:MAX_ENTRY_POINTS]}
    if len(entry_points) > MAX_ENTRY_POINTS:
        payload["omitted_count"] = len(entry_points) - MAX_ENTRY_POINTS
    return json.dumps(payload, indent=2)


def collect_reachable_sinks(terrain_payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings = terrain_payload.get("findings", [])
    if not isinstance(findings, list):
        return []

    sinks: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        file_path = one_line_text(finding.get("file", ""))
        sink_description = one_line_text(finding.get("sink_description", ""))
        sink_line = normalize_positive_int(finding.get("sink_line"))
        if not file_path or sink_line is None or not sink_description:
            continue
        item = (file_path, sink_line, sink_description)
        if item in seen:
            continue
        seen.add(item)
        sinks.append({"file": file_path, "line": sink_line, "description": sink_description})

    return sorted(sinks, key=lambda item: (item["file"], item["line"], item["description"]))


def build_sinks_block(terrain_payload: dict[str, Any]) -> str:
    sinks = collect_reachable_sinks(terrain_payload)
    payload: dict[str, Any] = {"reachable_sinks": sinks[:MAX_SINKS]}
    if len(sinks) > MAX_SINKS:
        payload["omitted_count"] = len(sinks) - MAX_SINKS
    return json.dumps(payload, indent=2)


def highest_severity_name(triage_payload: dict[str, Any]) -> str:
    counts = triage_payload.get("summary", {}).get("counts", {})
    for severity in ("critical", "high", "medium", "low"):
        if int(counts.get(severity, 0) or 0) > 0:
            return severity
    return "low"


def build_highest_severity_block(triage_payload: dict[str, Any]) -> str:
    findings = triage_payload.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    highest = highest_severity_name(triage_payload)
    matching: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if one_line_text(finding.get("severity", "")).lower() != highest:
            continue
        matching.append(
            {
                "file": one_line_text(finding.get("file", "unknown")),
                "line": normalize_positive_int(finding.get("line")) or 0,
                "finding": one_line_text(finding.get("finding") or finding.get("message", "")),
            }
        )

    payload: dict[str, Any] = {
        "highest_severity": highest.upper(),
        "count": len(matching),
        "findings": matching[:MAX_PRIORITY_FINDINGS],
    }
    if len(matching) > MAX_PRIORITY_FINDINGS:
        payload["omitted_count"] = len(matching) - MAX_PRIORITY_FINDINGS
    return json.dumps(payload, indent=2)


def build_user_prompt(
    domain_context: dict[str, Any],
    terrain_payload: dict[str, Any],
    triage_payload: dict[str, Any],
    pr_title: str,
    pr_description: str | None,
) -> str:
    return prompt_loader.render(
        "threat_model",
        "user_template",
        pr_title=pr_title,
        pr_description_section=build_pr_description_section(pr_description),
        domain_summary=build_domain_summary(domain_context),
        changed_files_block=build_changed_files_block(terrain_payload),
        entry_points_block=build_entry_points_block(terrain_payload),
        sinks_block=build_sinks_block(terrain_payload),
        highest_severity_block=build_highest_severity_block(triage_payload),
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
        raise ValueError("Threat model response must be a JSON object.")
    return parsed


def normalize_text_list(value: Any, *, limit: int | None = None) -> list[str]:
    if not isinstance(value, list):
        return []

    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        cleaned = one_line_text(item)
        if not cleaned or cleaned.lower() in {"unknown", "none", "null"}:
            continue
        if cleaned in seen:
            continue
        seen.add(cleaned)
        normalized.append(cleaned)
        if limit is not None and len(normalized) >= limit:
            break
    return normalized


def normalize_entry_points_added(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        file_path = one_line_text(item.get("file", ""))
        line = normalize_positive_int(item.get("line"))
        description = one_line_text(item.get("description", ""))
        if not file_path or line is None or not description:
            continue
        key = (file_path, line, description)
        if key in seen:
            continue
        seen.add(key)
        normalized.append({"file": file_path, "line": line, "description": description})
    return sorted(normalized, key=lambda item: (item["file"], item["line"], item["description"]))


def trim_to_one_sentence(text: Any) -> str:
    cleaned = one_line_text(text)
    if not cleaned:
        return ""
    for delimiter in (". ", "! ", "? "):
        if delimiter in cleaned:
            sentence = cleaned.split(delimiter, 1)[0].strip()
            terminal = delimiter.strip()
            if sentence and sentence[-1] not in ".!?":
                sentence += terminal
            return sentence
    if cleaned[-1] not in ".!?":
        cleaned += "."
    return cleaned


def normalize_threat_model(
    payload: dict[str, Any],
    *,
    pr_title: str,
    domain_summary: str,
) -> dict[str, Any]:
    if payload.get("generated") is False:
        return build_fallback_output()

    normalized = {
        "pr_title": one_line_text(payload.get("pr_title", pr_title)) or one_line_text(pr_title),
        "domain_summary": one_line_text(payload.get("domain_summary", domain_summary)),
        "entry_points_added": normalize_entry_points_added(payload.get("entry_points_added")),
        "assets_at_risk": normalize_text_list(payload.get("assets_at_risk")),
        "threat_actors": normalize_text_list(payload.get("threat_actors"), limit=3),
        "blast_radius": trim_to_one_sentence(payload.get("blast_radius", "")),
        "mitigations_present": normalize_text_list(payload.get("mitigations_present")),
        "mitigations_absent": normalize_text_list(payload.get("mitigations_absent")),
        "domain_risks": normalize_text_list(payload.get("domain_risks")),
        "generated": True,
    }

    if normalized["domain_summary"].lower() == "unknown":
        normalized["domain_risks"] = []
    return normalized


def generate_threat_model(
    domain_context: dict[str, Any],
    terrain_payload: dict[str, Any],
    triage_payload: dict[str, Any],
    pr_title: str,
    pr_description: str | None,
    provider: dict[str, str],
) -> dict[str, Any]:
    domain_summary = build_domain_summary(domain_context)
    text = ai_provider.generate_text(
        build_system_prompt(),
        build_user_prompt(domain_context, terrain_payload, triage_payload, pr_title, pr_description),
        provider,
        max_tokens=MAX_RESPONSE_TOKENS,
    )
    payload = parse_json_object(text)
    return normalize_threat_model(payload, pr_title=pr_title, domain_summary=domain_summary)


def build_threat_model_output(
    domain_context: dict[str, Any],
    terrain_payload: dict[str, Any],
    triage_payload: dict[str, Any],
    pr_title: str,
    pr_description: str | None = None,
) -> dict[str, Any]:
    provider = select_provider()
    if provider is None:
        return build_fallback_output()

    try:
        return generate_threat_model(
            domain_context,
            terrain_payload,
            triage_payload,
            pr_title,
            pr_description,
            provider,
        )
    except Exception as exc:
        print(f"Warning: threat model generation failed ({provider['name']}): {exc}", file=sys.stderr)
        return build_fallback_output()


def serialize_output(payload: dict[str, Any]) -> str:
    if payload == build_fallback_output():
        return json.dumps(payload)
    return json.dumps(payload, indent=2)


def main() -> int:
    args = parse_args()
    domain_context = load_json_object(args.domain_context, "domain context")
    terrain_payload = load_json_object(args.terrain, "terrain")
    triage_payload = load_json_object(args.triage, "triage")

    if domain_context is None or terrain_payload is None or triage_payload is None:
        output = build_fallback_output()
    else:
        output = build_threat_model_output(
            domain_context,
            terrain_payload,
            triage_payload,
            args.pr_title,
            args.pr_description,
        )

    Path(args.output).write_text(serialize_output(output), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
