#!/usr/bin/env python3
"""Post triaged findings to a pull request as a markdown comment."""

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
    parser.add_argument("--input", required=True, help="Triaged findings JSON path.")
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
    header = (
        "| Severity | File | Line | Finding | CWE | Fix Suggestion |\n"
        "| --- | --- | --- | --- | --- | --- |"
    )
    rows = []
    for finding in findings:
        rows.append(
            "| {severity} | `{file}` | {line} | {message} | {cwe} | {fix} |".format(
                severity=finding["severity"].upper(),
                file=finding["file"],
                line=finding["line"],
                message=escape_pipes(finding["finding"]),
                cwe=escape_pipes(finding["cwe"]),
                fix=escape_pipes(finding["fix_suggestion"]),
            )
        )
    return "\n".join([header, *rows])


def escape_pipes(value: str) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def build_comment_body(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    findings = payload["findings"]
    counts = summary["counts"]
    scanned_files = payload["source"]["scanned_files"]
    changed_files = payload["source"]["changed_files"]
    changed_file_count = len(changed_files) or len(scanned_files)
    status_line = (
        "Status: failing because at least one critical finding was detected."
        if summary["has_critical"]
        else "Status: passing. No critical findings detected."
    )

    lines = [
        COMMENT_MARKER,
        "## PR Security Gate Results",
        "",
        status_line,
        "",
        (
            f"Scanned `{len(scanned_files)}` changed source file(s) "
            f"out of `{changed_file_count}` changed file(s)."
        ),
        (
            f"Findings: critical `{counts['critical']}`, high `{counts['high']}`, "
            f"medium `{counts['medium']}`, low `{counts['low']}`."
        ),
        "",
    ]

    if findings:
        lines.append(build_table(findings))
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
