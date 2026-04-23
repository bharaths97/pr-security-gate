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

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


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
    return "medium"


def finding_key(finding: dict[str, Any]) -> tuple[str, str, int]:
    return (
        str(finding["rule_id"]),
        str(finding["file"]),
        int(finding["line"]),
    )


def normalize_finding(result: dict[str, Any]) -> dict[str, Any]:
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})
    severity = normalize_severity(metadata.get("severity") or extra.get("severity"))
    start = result.get("start", {})
    return {
        "rule_id": result.get("check_id", "unknown-rule"),
        "severity": severity,
        "score": SEVERITY_RANK[severity],
        "file": result.get("path", ""),
        "line": int(start.get("line", 1)),
        "finding": extra.get("message", "Security finding detected."),
        "cwe": metadata.get("cwe", "N/A"),
        "fix_suggestion": metadata.get("fix", "Review and remediate this issue."),
    }


def deduplicate_findings(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, str, int], dict[str, Any]] = {}
    for result in results:
        finding = normalize_finding(result)
        key = finding_key(finding)
        existing = deduped.get(key)
        if existing is None or finding["score"] > existing["score"]:
            deduped[key] = finding
    return sort_findings(list(deduped.values()))


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (-item["score"], item["file"], item["line"], item["rule_id"]),
    )


def group_findings_by_severity(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped = {severity: [] for severity in SEVERITY_ORDER}
    for finding in findings:
        grouped[finding["severity"]].append(finding)
    for severity in SEVERITY_ORDER:
        grouped[severity] = sort_findings(grouped[severity])
    return grouped


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
    grouped_findings = group_findings_by_severity(findings)
    output = {
        "summary": build_summary(findings),
        "findings": findings,
        "grouped_findings": grouped_findings,
        "source": {
            "scanner": payload.get("metadata", {}).get("scanner", "semgrep"),
            "changed_files": payload.get("paths", {}).get("changed", []),
            "scanned_files": payload.get("paths", {}).get("scanned", []),
            "reason": payload.get("metadata", {}).get("reason", ""),
        },
    }
    Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
