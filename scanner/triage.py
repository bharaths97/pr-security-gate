#!/usr/bin/env python3
"""Deduplicate Semgrep findings and normalize severity metadata."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

SEVERITY_ORDER = sorted(SEVERITY_RANK, key=SEVERITY_RANK.__getitem__, reverse=True)
SEVERITY_ALIASES = {
    "error": "high",
    "warning": "medium",
    "info": "low",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Raw Semgrep JSON payload.")
    parser.add_argument("--output", required=True, help="Normalized findings JSON path.")
    return parser.parse_args()


def normalize_severity(value: str | None) -> str:
    if not value:
        return "medium"
    normalized = value.strip().lower()
    if normalized in SEVERITY_RANK:
        return normalized
    if normalized in SEVERITY_ALIASES:
        return SEVERITY_ALIASES[normalized]
    return "medium"


def finding_key(finding: dict[str, Any]) -> tuple[str, str, int]:
    return (
        str(finding["rule_id"]),
        str(finding["file"]),
        int(finding["line"]),
    )


def location_key(finding: dict[str, Any]) -> tuple[str, int]:
    return (
        str(finding["file"]),
        int(finding["line"]),
    )


def normalize_finding(result: dict[str, Any]) -> dict[str, Any]:
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})
    severity = normalize_severity(metadata.get("severity") or extra.get("severity"))
    start = result.get("start", {})
    finding = {
        "rule_id": result.get("check_id", "unknown-rule"),
        "severity": severity,
        "file": result.get("path", ""),
        "line": int(start.get("line", 1)),
        "finding": extra.get("message", "Security finding detected."),
        "cwe": normalize_cwe(metadata.get("cwe")),
        "fix_suggestion": metadata.get("fix", "Review and remediate this issue."),
    }
    lines = normalize_lines(extra.get("lines"))
    if lines is not None:
        finding["lines"] = lines
    return finding


def normalize_cwe(value: Any) -> str:
    if isinstance(value, list):
        cleaned = [str(item).strip() for item in value if str(item).strip()]
        return ", ".join(cleaned) if cleaned else "N/A"
    if value is None:
        return "N/A"
    cleaned = str(value).strip()
    return cleaned or "N/A"


def normalize_lines(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        text = "\n".join(str(item) for item in value)
    else:
        text = str(value)
    return text if text.strip() else None


def get_rule_ids(finding: dict[str, Any]) -> list[str]:
    raw_rule_ids = finding.get("rule_ids")
    if isinstance(raw_rule_ids, list):
        values = raw_rule_ids
    else:
        values = [finding.get("rule_id")]
    normalized: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in normalized:
            normalized.append(text)
    return normalized


def merge_rule_ids(primary: dict[str, Any], secondary: dict[str, Any]) -> None:
    merged = get_rule_ids(primary)
    for rule_id in get_rule_ids(secondary):
        if rule_id not in merged:
            merged.append(rule_id)
    if len(merged) > 1:
        primary["rule_ids"] = merged


def dedup_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, int], dict[str, Any]] = {}
    for finding in findings:
        key = location_key(finding)
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = finding
            continue

        merge_rule_ids(existing, finding)
        if SEVERITY_RANK[finding["severity"]] > SEVERITY_RANK[existing["severity"]]:
            replacement = dict(finding)
            merge_rule_ids(replacement, existing)
            deduped[key] = replacement

    return sort_findings(list(deduped.values()))


def deduplicate_findings(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = [normalize_finding(result) for result in results]
    return dedup_findings(findings)


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (-SEVERITY_RANK[item["severity"]], item["file"], item["line"], item["rule_id"]),
    )


def build_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1
    return {
        "total": len(findings),
        "counts": counts,
        "has_critical": counts["critical"] > 0,
    }


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    findings = deduplicate_findings(payload.get("results", []))
    output = {
        "summary": build_summary(findings),
        "findings": findings,
        "source": {
            "scanner": payload.get("metadata", {}).get("scanner", "semgrep"),
            "changed_files": payload.get("paths", {}).get("changed", []),
            "scanned_files": payload.get("paths", {}).get("scanned", []),
            "reason": payload.get("metadata", {}).get("reason", ""),
            "base_sha": payload.get("metadata", {}).get("base_sha", ""),
            "head_sha": payload.get("metadata", {}).get("head_sha", ""),
        },
    }
    Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
