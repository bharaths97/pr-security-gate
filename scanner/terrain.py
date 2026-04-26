#!/usr/bin/env python3
"""Optionally synthesize per-file taint terrain for triaged findings."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from scanner import ai_provider, prompt_loader


MAX_RESPONSE_TOKENS = 1200
HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
select_provider = ai_provider.select_provider


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Triaged findings JSON path.")
    parser.add_argument("--output", required=True, help="Terrain findings JSON path.")
    parser.add_argument(
        "--context",
        help="Optional domain context JSON path.",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root used to read changed files and git diff metadata.",
    )
    parser.add_argument(
        "--base-sha",
        default=os.getenv("GITHUB_BASE_SHA"),
        help="Optional base commit SHA. Falls back to input JSON metadata or GITHUB_BASE_SHA.",
    )
    parser.add_argument(
        "--head-sha",
        default=os.getenv("GITHUB_HEAD_SHA"),
        help="Optional head commit SHA. Falls back to input JSON metadata or GITHUB_HEAD_SHA.",
    )
    return parser.parse_args()


def build_output_payload(payload: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    output = dict(payload)
    output["findings"] = findings
    return output


def build_system_prompt() -> str:
    return prompt_loader.render("terrain", "system")


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


def format_numbered_file(content: str) -> str:
    return "\n".join(f"{index:4}: {line}" for index, line in enumerate(content.splitlines(), start=1))


def build_file_findings_block(findings: list[dict[str, Any]]) -> str:
    block = {
        "findings": [
            {
                "rule_id": str(finding.get("rule_id", "unknown-rule")),
                "severity": str(finding.get("severity", "unknown")),
                "line": int(finding.get("line", 0) or 0),
                "finding": one_line_text(finding.get("finding", "")),
                "cwe": one_line_text(finding.get("cwe", "N/A")),
                "lines": one_line_text(finding.get("lines", "unknown")),
            }
            for finding in findings
        ]
    }
    return json.dumps(block, indent=2)


def build_user_prompt(
    file_path: str,
    file_content: str,
    findings: list[dict[str, Any]],
    domain_context: dict[str, Any] | None,
) -> str:
    return prompt_loader.render(
        "terrain",
        "user_template",
        domain_summary=build_domain_summary(domain_context),
        file_path=file_path,
        file_findings=build_file_findings_block(findings),
        file_content=format_numbered_file(file_content),
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
        raise ValueError("Terrain response must be a JSON object.")
    return parsed


def normalize_line_number(value: Any) -> int | None:
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
        if parsed > 0:
            return parsed
    return None


def normalize_nodes(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        line = normalize_line_number(item.get("line"))
        description = one_line_text(item.get("description", ""))
        if line is None or not description:
            continue
        normalized.append({"line": line, "description": description})
    return sorted(normalized, key=lambda item: (item["line"], item["description"]))


def normalize_terrain_map(value: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(value, dict):
        raise ValueError("Terrain response must be a JSON object.")
    return {
        "sources": normalize_nodes(value.get("sources")),
        "sinks": normalize_nodes(value.get("sinks")),
    }


def select_closest_node(nodes: list[dict[str, Any]], line: int) -> dict[str, Any] | None:
    if not nodes:
        return None
    earlier = [node for node in nodes if node["line"] <= line]
    candidates = earlier or nodes
    return min(candidates, key=lambda item: (abs(item["line"] - line), item["line"]))


def build_taint_path(source: dict[str, Any] | None, sink: dict[str, Any] | None) -> str | None:
    if source is None or sink is None:
        return None
    return (
        f"{source['description']} (line {source['line']}) -> "
        f"{sink['description']} (line {sink['line']})"
    )


def mark_file_unknown(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    updated_findings: list[dict[str, Any]] = []
    for finding in findings:
        updated = dict(finding)
        updated["origin"] = "unknown"
        updated_findings.append(updated)
    return updated_findings


def classify_origin(source_line: int | None, added_lines: set[int] | None) -> str:
    if source_line is None or added_lines is None:
        return "unknown"
    return "introduced" if source_line in added_lines else "pre-existing"


def classify_file_findings(
    findings: list[dict[str, Any]],
    terrain_map: dict[str, list[dict[str, Any]]],
    added_lines: set[int] | None,
) -> list[dict[str, Any]]:
    updated_findings: list[dict[str, Any]] = []
    sources = terrain_map.get("sources", [])
    sinks = terrain_map.get("sinks", [])

    for finding in findings:
        updated = dict(finding)
        finding_line = int(finding.get("line", 0) or 0)
        source = select_closest_node(sources, finding_line)
        sink = select_closest_node(sinks, finding_line)
        taint_path = build_taint_path(source, sink)

        updated["origin"] = classify_origin(source["line"] if source else None, added_lines)
        if source is not None:
            updated["source_line"] = source["line"]
            updated["source_description"] = source["description"]
        if sink is not None:
            updated["sink_line"] = sink["line"]
            updated["sink_description"] = sink["description"]
        if taint_path is not None:
            updated["taint_path"] = taint_path
        updated_findings.append(updated)

    return updated_findings


def resolve_diff_range(
    payload: dict[str, Any],
    base_sha: str | None,
    head_sha: str | None,
) -> tuple[str | None, str | None]:
    source = payload.get("source", {})
    resolved_base = base_sha or source.get("base_sha")
    resolved_head = head_sha or source.get("head_sha")
    return resolved_base or None, resolved_head or None


def collect_added_lines(repo_root: Path, file_path: str, base_sha: str | None, head_sha: str | None) -> set[int] | None:
    if not base_sha or not head_sha:
        return None

    result = subprocess.run(
        ["git", "diff", "--unified=0", f"{base_sha}..{head_sha}", "--", file_path],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )

    added_lines: set[int] = set()
    for line in result.stdout.splitlines():
        match = HUNK_HEADER_RE.match(line)
        if not match:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or "1")
        for line_number in range(start, start + count):
            added_lines.add(line_number)
    return added_lines


def read_changed_file(repo_root: Path, file_path: str) -> str:
    return (repo_root / file_path).read_text(encoding="utf-8", errors="replace")


def generate_file_terrain(
    provider: dict[str, str],
    file_path: str,
    file_content: str,
    findings: list[dict[str, Any]],
    domain_context: dict[str, Any] | None,
) -> dict[str, list[dict[str, Any]]]:
    response = ai_provider.generate_text(
        build_system_prompt(),
        build_user_prompt(file_path, file_content, findings, domain_context),
        provider,
        max_tokens=MAX_RESPONSE_TOKENS,
    )
    return normalize_terrain_map(parse_json_object(response))


def group_findings_by_file(findings: list[dict[str, Any]]) -> list[tuple[str, list[dict[str, Any]]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        grouped.setdefault(str(finding.get("file", "")), []).append(finding)
    return list(grouped.items())


def synthesize_terrain(
    payload: dict[str, Any],
    repo_root: Path,
    domain_context: dict[str, Any] | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
) -> dict[str, Any]:
    findings = [dict(finding) for finding in payload.get("findings", [])]
    if not findings:
        return build_output_payload(payload, findings)

    provider = select_provider()
    if provider is None:
        return build_output_payload(payload, findings)

    resolved_base_sha, resolved_head_sha = resolve_diff_range(payload, base_sha, head_sha)
    updated_findings: list[dict[str, Any]] = []

    for file_path, file_findings in group_findings_by_file(findings):
        try:
            file_content = read_changed_file(repo_root, file_path)
            added_lines = collect_added_lines(repo_root, file_path, resolved_base_sha, resolved_head_sha)
            terrain_map = generate_file_terrain(provider, file_path, file_content, file_findings, domain_context)
            updated_findings.extend(classify_file_findings(file_findings, terrain_map, added_lines))
        except Exception as exc:
            print(f"Warning: terrain synthesis failed for {file_path} ({provider['name']}): {exc}", file=sys.stderr)
            updated_findings.extend(mark_file_unknown(file_findings))

    return build_output_payload(payload, updated_findings)


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    domain_context = load_domain_context(args.context)
    output = synthesize_terrain(
        payload,
        Path(args.repo_root).resolve(),
        domain_context=domain_context,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
    )
    Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
