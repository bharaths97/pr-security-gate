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


def build_table(findings: list[dict[str, Any]]) -> str:
    include_taint_path = any(finding.get("taint_path") for finding in findings)
    header = (
        "| Severity | File | Line | Finding | Taint Path | CWE | Fix Suggestion |\n"
        "| --- | --- | --- | --- | --- | --- | --- |"
        if include_taint_path
        else (
            "| Severity | File | Line | Finding | CWE | Fix Suggestion |\n"
            "| --- | --- | --- | --- | --- | --- |"
        )
    )
    rows = []
    for finding in findings:
        values = {
            "severity": severity_with_origin(finding),
            "file": finding["file"],
            "line": finding["line"],
            "message": escape_pipes(preferred_finding_text(finding)),
            "cwe": escape_pipes(finding["cwe"]),
            "fix": escape_pipes(preferred_fix_text(finding)),
            "taint_path": escape_pipes(str(finding.get("taint_path", ""))),
        }
        if include_taint_path:
            rows.append(
                "| {severity} | `{file}` | {line} | {message} | {taint_path} | {cwe} | {fix} |".format(**values)
            )
        else:
            rows.append(
                "| {severity} | `{file}` | {line} | {message} | {cwe} | {fix} |".format(**values)
            )
    return "\n".join([header, *rows])


def escape_pipes(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def preferred_finding_text(finding: dict[str, Any]) -> str:
    return str(finding.get("enriched_finding") or finding.get("finding", ""))


def preferred_fix_text(finding: dict[str, Any]) -> str:
    return str(finding.get("enriched_fix") or finding.get("fix_suggestion", ""))


def severity_with_origin(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity", "unknown")).upper()
    origin = str(finding.get("origin", "")).strip().lower()
    if origin == "introduced":
        return f"{severity}<br>NEW"
    if origin == "pre-existing":
        return f"{severity}<br>PRE-EXISTING"
    return severity


def split_findings(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active: list[dict[str, Any]] = []
    pre_existing: list[dict[str, Any]] = []
    for finding in findings:
        if str(finding.get("origin", "")).strip().lower() == "pre-existing":
            pre_existing.append(finding)
        else:
            active.append(finding)
    return active, pre_existing


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

    active_findings, pre_existing_findings = split_findings(findings)

    if findings:
        if active_findings:
            lines.append(build_table(active_findings))
        else:
            lines.append("No introduced or unclassified findings are present in the main results table.")
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
