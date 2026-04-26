#!/usr/bin/env python3
"""Post findings to a pull request as a markdown comment."""

from __future__ import annotations

import argparse
import json
import os
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
    include_taint_path = any(finding.get("taint_path") for finding in findings)
    columns = ["Severity", "File", "Line", "Finding"]
    if include_taint_path:
        columns.append("Taint Path")
    columns.append("CWE")
    if include_counter_argument:
        columns.append("Counter-Argument")
    columns.append("Fix Suggestion")
    header = "| " + " | ".join(columns) + " |\n| " + " | ".join(["---"] * len(columns)) + " |"
    rows = []
    for finding in findings:
        row = [
            severity_with_origin(finding),
            f"`{finding['file']}`",
            str(finding["line"]),
            escape_pipes(preferred_finding_text(finding, include_counter_argument=include_counter_argument)),
        ]
        if include_taint_path:
            row.append(escape_pipes(str(finding.get("taint_path", ""))))
        row.append(escape_pipes(finding["cwe"]))
        if include_counter_argument:
            row.append(escape_pipes(str(finding.get("counter_argument", ""))))
        row.append(escape_pipes(preferred_fix_text(finding)))
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


def escape_pipes(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def preferred_finding_text(finding: dict[str, Any], include_counter_argument: bool = False) -> str:
    text = str(finding.get("enriched_finding") or finding.get("finding", ""))
    if include_counter_argument:
        return text

    note = adversarial_note_for_main_table(finding)
    if not note:
        return text
    return f"{text} ({note})"


def preferred_fix_text(finding: dict[str, Any]) -> str:
    return str(finding.get("enriched_fix") or finding.get("fix_suggestion", ""))


def one_line_text(value: Any) -> str:
    return " ".join(str(value).split())


def normalize_verdict(value: Any) -> str:
    return one_line_text(value).lower()


def adversarial_note_for_main_table(finding: dict[str, Any]) -> str:
    verdict = normalize_verdict(finding.get("verdict", ""))
    severity = str(finding.get("severity", "")).strip().lower()
    counter_argument = one_line_text(finding.get("counter_argument", ""))

    if verdict == "sustained":
        note = "Adversarial review: sustained"
    elif verdict == "downgraded" and severity == "critical":
        note = "Adversarial review: downgraded"
    else:
        return ""

    if counter_argument:
        return f"{note}. {counter_argument}"
    return note


def severity_with_origin(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity", "unknown")).upper()
    origin = str(finding.get("origin", "")).strip().lower()
    if origin == "introduced":
        return f"{severity}<br>NEW"
    if origin == "pre-existing":
        return f"{severity}<br>PRE-EXISTING"
    return severity


def split_findings(
    findings: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    main_findings: list[dict[str, Any]] = []
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
        main_findings.append(finding)

    active: list[dict[str, Any]] = []
    for finding in main_findings:
        if str(finding.get("origin", "")).strip().lower() == "pre-existing":
            pre_existing.append(finding)
        else:
            active.append(finding)
    return active, challenged, pre_existing, cross_file


def format_blockquote(text: str) -> list[str]:
    return [f"> {line}".rstrip() for line in str(text).splitlines() if line.strip()]


def build_comment_body(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    findings = payload["findings"]
    narrative = payload.get("narrative")
    counts = summary["counts"]
    source = payload["source"]
    scanned_files = source["scanned_files"]
    changed_files = source["changed_files"]
    changed_file_count = len(changed_files) or len(scanned_files)
    is_cloud = source.get("scanner", "").startswith("semgrep-cloud")
    status_line = (
        "Status: failing because at least one critical finding was detected."
        if summary["has_critical"]
        else "Status: passing. No critical findings detected."
    )

    lines = [
        COMMENT_MARKER,
        "## PR Security Gate Results",
        "",
    ]

    if findings and narrative:
        lines.extend(format_blockquote(narrative))
        lines.append("")

    lines.extend(
        [
            status_line,
            "",
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

    active_findings, challenged_findings, pre_existing_findings, cross_file_findings = split_findings(findings)

    if findings:
        if active_findings:
            lines.append(build_table(active_findings))
        else:
            lines.append("No introduced or unclassified findings are present in the main results table.")
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


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
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
