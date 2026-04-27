#!/usr/bin/env python3
"""Post findings to a pull request as a markdown comment."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

COMMENT_MARKER = "<!-- pr-security-gate -->"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Narrative findings JSON path.")
    parser.add_argument(
        "--output",
        help="Optional path to write the rendered markdown comment body.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Render the markdown comment without posting it to GitHub.",
    )
    return parser.parse_args()


def build_table(findings: list[dict[str, Any]], include_counter_argument: bool = False) -> str:
    columns = ["Badge", "Finding", "Severity", "Fix Suggestion"]
    header = "| " + " | ".join(columns) + " |\n| " + " | ".join(["---"] * len(columns)) + " |"
    rows = []
    for finding in findings:
        row = [
            badge_for_finding(finding),
            render_finding_cell(finding, include_counter_argument=include_counter_argument),
            severity_label(finding),
            render_fix_cell(finding),
        ]
        rows.append("| " + " | ".join(row) + " |")
    return "\n".join([header, *rows])


def build_extended_analysis_table(findings: list[dict[str, Any]]) -> str:
    columns = ["File", "Line", "Confidence", "Chain"]
    header = "| " + " | ".join(columns) + " |\n| " + " | ".join(["---"] * len(columns)) + " |"
    rows = []
    for finding in findings:
        rows.append(
            "| "
            + " | ".join(
                [
                    f"`{finding['file']}`",
                    str(finding["line"]),
                    escape_pipes(str(finding.get("confidence", "low")).lower()),
                    escape_pipes(str(finding.get("chain", ""))),
                ]
            )
            + " |"
        )
    return "\n".join([header, *rows])


def build_auditor_notes_table(findings: list[dict[str, Any]]) -> str:
    columns = ["Badge", "Finding", "Severity", "Verdict", "AI Auditor Notes"]
    header = "| " + " | ".join(columns) + " |\n| " + " | ".join(["---"] * len(columns)) + " |"
    rows = []
    for finding in findings:
        rows.append(
            "| "
            + " | ".join(
                [
                    badge_for_finding(finding),
                    escape_pipes(location_label(finding)),
                    severity_label(finding),
                    escape_pipes(normalize_verdict(finding.get("verdict", "")) or "none"),
                    escape_pipes(trim_to_one_sentence(one_line_text(finding.get("counter_argument", "")), True))
                    or "No additional notes.",
                ]
            )
            + " |"
        )
    return "\n".join([header, *rows])


def escape_pipes(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def one_line_text(value: Any) -> str:
    return " ".join(str(value).split())


def normalize_verdict(value: Any) -> str:
    return one_line_text(value).lower()


def trim_to_one_sentence(text: str, ensure_terminal_period: bool = False) -> str:
    cleaned = one_line_text(text)
    if not cleaned:
        return ""
    match = re.match(r"^(.*?[.!?])(?:\s+|$)", cleaned)
    if match:
        sentence = match.group(1).strip()
    else:
        sentence = cleaned
    if ensure_terminal_period and sentence and sentence[-1] not in ".!?":
        sentence += "."
    return sentence


def strip_location_references(text: str, finding: dict[str, Any]) -> str:
    cleaned = one_line_text(text)
    file_path = one_line_text(finding.get("file", ""))
    file_name = Path(file_path).name if file_path else ""
    line = one_line_text(finding.get("line", ""))
    patterns = []
    if file_path and line:
        patterns.extend(
            [
                rf"{re.escape(file_path)}\s+at\s+line\s+{re.escape(line)}",
                rf"{re.escape(file_name)}\s+at\s+line\s+{re.escape(line)}",
                rf"{re.escape(file_path)}:{re.escape(line)}",
                rf"{re.escape(file_name)}:{re.escape(line)}",
            ]
        )
    for pattern in patterns:
        cleaned = re.sub(pattern, "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\(\s*\)", "", cleaned)
    cleaned = re.sub(r"\s+\.", ".", cleaned)
    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip(" -,:;")
    return cleaned


def severity_label(finding: dict[str, Any]) -> str:
    return str(finding.get("severity", "unknown")).upper()


def badge_for_finding(finding: dict[str, Any]) -> str:
    if normalize_verdict(finding.get("verdict", "")) == "insufficient_evidence":
        return "? Uncertain"
    badge = one_line_text(finding.get("badge", "")).upper()
    if badge:
        return badge
    origin = str(finding.get("origin", "")).strip().lower()
    if origin in {"introduced", "new"}:
        return "NEW"
    if origin == "pre-existing":
        return "PRE-EXISTING"
    return "-"


def location_label(finding: dict[str, Any]) -> str:
    return f"`{finding.get('file', 'unknown')}:{finding.get('line', '?')}`"


def preferred_finding_text(finding: dict[str, Any]) -> str:
    return str(finding.get("enriched_finding") or finding.get("finding") or finding.get("message", ""))


def preferred_fix_text(finding: dict[str, Any]) -> str:
    return str(finding.get("enriched_fix") or finding.get("fix_suggestion", ""))


def capped_cell_text(text: str, finding: dict[str, Any], ensure_terminal_period: bool = True) -> str:
    stripped = strip_location_references(text, finding)
    return trim_to_one_sentence(stripped, ensure_terminal_period)


def adversarial_note_for_main_table(finding: dict[str, Any]) -> str:
    verdict = normalize_verdict(finding.get("verdict", ""))
    severity = str(finding.get("severity", "")).strip().lower()
    counter_argument = capped_cell_text(str(finding.get("counter_argument", "")), finding, True)

    if severity == "critical":
        return ""

    if verdict == "sustained":
        note = "AI auditor: sustained"
    else:
        return ""

    if counter_argument:
        return f"{note} - {counter_argument}"
    return note


def render_finding_cell(finding: dict[str, Any], include_counter_argument: bool = False) -> str:
    main_text = capped_cell_text(preferred_finding_text(finding), finding, True) or "Security finding detected."
    rendered = escape_pipes(f"{location_label(finding)} {main_text}")
    details: list[str] = []

    taint_path = one_line_text(finding.get("taint_path", ""))
    if taint_path:
        details.append(f"<sub><em>Taint path: {escape_pipes(trim_to_one_sentence(taint_path, False))}</em></sub>")

    if include_counter_argument:
        counter_argument = capped_cell_text(str(finding.get("counter_argument", "")), finding, True)
        if counter_argument:
            details.append(f"<sub><em>AI auditor challenge: {escape_pipes(counter_argument)}</em></sub>")
    else:
        note = adversarial_note_for_main_table(finding)
        if note:
            details.append(f"<sub><em>{escape_pipes(note)}</em></sub>")

    for detail in details:
        rendered += "<br>" + detail
    return rendered


def render_fix_cell(finding: dict[str, Any]) -> str:
    text = capped_cell_text(preferred_fix_text(finding), finding, True)
    return escape_pipes(text or "Review and remediate this issue.")


def split_findings(
    findings: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    main_findings: list[dict[str, Any]] = []
    critical_auditor_notes: list[dict[str, Any]] = []
    challenged: list[dict[str, Any]] = []
    pre_existing: list[dict[str, Any]] = []
    cross_file: list[dict[str, Any]] = []

    for finding in findings:
        if str(finding.get("origin", "")).strip().lower() == "cross-file":
            cross_file.append(finding)
            continue
        if normalize_verdict(finding.get("verdict", "")) == "downgraded" and str(
            finding.get("severity", "")
        ).strip().lower() != "critical":
            challenged.append(finding)
            continue
        if str(finding.get("severity", "")).strip().lower() == "critical" and normalize_verdict(
            finding.get("verdict", "")
        ) in {"sustained", "downgraded", "insufficient_evidence"}:
            critical_auditor_notes.append(finding)
        main_findings.append(finding)

    active: list[dict[str, Any]] = []
    for finding in main_findings:
        if str(finding.get("origin", "")).strip().lower() == "pre-existing":
            pre_existing.append(finding)
        else:
            active.append(finding)
    return active, critical_auditor_notes, challenged, pre_existing, cross_file


def normalized_counts(summary: dict[str, Any]) -> dict[str, int]:
    return {
        "critical": int(summary.get("counts", {}).get("critical", 0) or 0),
        "high": int(summary.get("counts", {}).get("high", 0) or 0),
        "medium": int(summary.get("counts", {}).get("medium", 0) or 0),
        "low": int(summary.get("counts", {}).get("low", 0) or 0),
    }


def normalize_payload(payload: dict[str, Any], has_critical: bool | None = None) -> dict[str, Any]:
    normalized = dict(payload)
    findings = list(normalized.get("findings", []))
    summary = dict(normalized.get("summary", {}))
    counts = normalized_counts(summary)
    summary["counts"] = counts
    summary["total"] = int(summary.get("total", len(findings)) or 0)
    summary["has_critical"] = counts["critical"] > 0 if has_critical is None else bool(has_critical)
    normalized["summary"] = summary
    normalized["findings"] = findings
    normalized["source"] = dict(normalized.get("source", {}))
    return normalized


def build_status_line(summary: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    counts = normalized_counts(summary)
    if summary.get("has_critical"):
        return f"Status: failing - {counts['critical']} CRITICAL finding(s) detected"
    if not findings:
        return "Status: passing - no findings detected"
    if counts["high"] > 0:
        return f"Status: passing - {counts['high']} HIGH finding(s) require review before merge"
    return "Status: passing - no blocking findings"


def build_comment_body(payload: dict[str, Any]) -> str:
    payload = normalize_payload(payload)
    summary = payload["summary"]
    findings = payload["findings"]
    narrative = payload.get("narrative")
    counts = summary["counts"]
    source = payload.get("source", {})
    scanned_files = source.get("scanned_files", [])
    changed_files = source.get("changed_files", [])
    changed_file_count = len(changed_files) or len(scanned_files)
    is_cloud = source.get("scanner", "").startswith("semgrep-cloud")
    status_line = build_status_line(summary, findings)

    lines = [
        COMMENT_MARKER,
        "## PR Security Gate Results",
        "",
        status_line,
        "",
    ]

    if findings and narrative:
        lines.extend([one_line_text(narrative), ""])

    lines.extend(
        [
            (
                f"Scanned full repository (`{changed_file_count}` changed file(s) in this PR)."
                if is_cloud
                else (
                    f"Scanned `{len(scanned_files)}` changed source file(s) "
                    f"out of `{changed_file_count}` changed file(s)."
                )
            ),
            (
                f"Findings: critical `{counts['critical']}`, high `{counts['high']}`, "
                f"medium `{counts['medium']}`, low `{counts['low']}`."
            ),
            "",
        ]
    )

    (
        active_findings,
        critical_auditor_notes,
        challenged_findings,
        pre_existing_findings,
        cross_file_findings,
    ) = split_findings(findings)

    if findings:
        if active_findings:
            lines.append(build_table(active_findings))
        else:
            lines.append("No introduced or unclassified findings are present in the main results table.")
        if critical_auditor_notes:
            lines.extend(
                [
                    "",
                    "<details>",
                    f"<summary>AI auditor notes — does not affect gate decision ({len(critical_auditor_notes)})</summary>",
                    "",
                    build_auditor_notes_table(critical_auditor_notes),
                    "",
                    "</details>",
                ]
            )
        if challenged_findings:
            lines.extend(
                [
                    "",
                    "<details>",
                    f"<summary>Challenged findings ({len(challenged_findings)})</summary>",
                    "",
                    build_table(challenged_findings, include_counter_argument=True),
                    "",
                    "</details>",
                ]
            )
        if pre_existing_findings:
            lines.extend(
                [
                    "",
                    "<details>",
                    f"<summary>Pre-existing findings ({len(pre_existing_findings)})</summary>",
                    "",
                    build_table(pre_existing_findings),
                    "",
                    "</details>",
                ]
            )
        if cross_file_findings:
            lines.extend(
                [
                    "",
                    "<details>",
                    f"<summary>Extended Analysis ({len(cross_file_findings)})</summary>",
                    "",
                    "Low-confidence cross-file chains that originate in the diff and appear to reach a downstream sink:",
                    "",
                    build_extended_analysis_table(cross_file_findings),
                    "",
                    "</details>",
                ]
            )
    else:
        lines.append("No security findings were detected in the changed files.")

    if summary["has_critical"]:
        lines.extend(
            [
                "",
                "> Critical findings detected. This check fails so branch protection can block the merge until remediated.",
            ]
        )

    return "\n".join(lines)


def upsert_comment(repo_name: str, pr_number: int, token: str, body: str) -> None:
    from github import Github

    client = Github(token)
    repo = client.get_repo(repo_name)
    pull_request = repo.get_pull(pr_number)

    for comment in pull_request.get_issue_comments():
        if COMMENT_MARKER in comment.body:
            comment.edit(body)
            return

    pull_request.create_issue_comment(body)


def render_comment(payload: dict[str, Any], has_critical: bool | None = None) -> str:
    return build_comment_body(normalize_payload(payload, has_critical=has_critical))


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    payload = normalize_payload(payload)
    body = build_comment_body(payload)

    if args.output:
        Path(args.output).write_text(body, encoding="utf-8")

    if args.dry_run:
        print(body)
        return 1 if payload["summary"]["has_critical"] else 0

    token = os.getenv("GITHUB_TOKEN")
    repo_name = os.getenv("GITHUB_REPOSITORY")
    pr_number = os.getenv("PR_NUMBER")

    if not token or not repo_name or not pr_number:
        raise SystemExit("GITHUB_TOKEN, GITHUB_REPOSITORY, and PR_NUMBER must be set unless --dry-run is used.")

    upsert_comment(repo_name, int(pr_number), token, body)

    return 1 if payload["summary"]["has_critical"] else 0


if __name__ == "__main__":
    sys.exit(main())
