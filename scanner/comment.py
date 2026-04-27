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
THREAT_MODEL_COMMENT_MARKER = "<!-- pr-threat-model -->"


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
    parser.add_argument(
        "--threat-model",
        help="Optional threat model JSON path for a separate advisory comment.",
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
                    escape_pipes(
                        adversarial_explanation_for_render(finding, prefer_counter_argument=True)
                    )
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


def adversarial_explanation_for_render(
    finding: dict[str, Any],
    *,
    prefer_counter_argument: bool = False,
) -> str:
    rationale = capped_cell_text(str(finding.get("rationale", "")), finding, True)
    counter_argument = capped_cell_text(str(finding.get("counter_argument", "")), finding, True)

    if prefer_counter_argument and counter_argument:
        return counter_argument
    if rationale:
        return rationale
    return counter_argument


def adversarial_note_for_main_table(finding: dict[str, Any]) -> str:
    verdict = normalize_verdict(finding.get("verdict", ""))
    severity = str(finding.get("severity", "")).strip().lower()
    explanation = adversarial_explanation_for_render(finding)

    if severity == "critical":
        return ""

    if verdict == "sustained":
        note = "AI auditor: sustained"
    elif verdict == "insufficient_evidence":
        note = "AI auditor: uncertain"
    else:
        return ""

    if explanation:
        return f"{note} - {explanation}"
    return note


def render_finding_cell(finding: dict[str, Any], include_counter_argument: bool = False) -> str:
    main_text = capped_cell_text(preferred_finding_text(finding), finding, True) or "Security finding detected."
    rendered = escape_pipes(f"{location_label(finding)} {main_text}")
    details: list[str] = []

    taint_path = one_line_text(finding.get("taint_path", ""))
    if taint_path:
        details.append(f"<sub><em>Taint path: {escape_pipes(trim_to_one_sentence(taint_path, False))}</em></sub>")

    if include_counter_argument:
        explanation = adversarial_explanation_for_render(finding, prefer_counter_argument=True)
        if explanation:
            details.append(f"<sub><em>AI auditor challenge: {escape_pipes(explanation)}</em></sub>")
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


def normalize_string_list(value: Any) -> list[str]:
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
    return normalized


def normalize_entry_points(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        file_path = one_line_text(item.get("file", ""))
        description = one_line_text(item.get("description", ""))
        line_value = item.get("line")
        if isinstance(line_value, int):
            line = line_value
        elif isinstance(line_value, str) and line_value.strip().isdigit():
            line = int(line_value.strip())
        else:
            line = 0
        if not file_path or line <= 0 or not description:
            continue
        key = (file_path, line, description)
        if key in seen:
            continue
        seen.add(key)
        normalized.append({"file": file_path, "line": line, "description": description})
    return normalized


def normalize_threat_model_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("generated") is not True:
        return {"generated": False}

    return {
        "generated": True,
        "entry_points_added": normalize_entry_points(payload.get("entry_points_added")),
        "assets_at_risk": normalize_string_list(payload.get("assets_at_risk")),
        "threat_actors": normalize_string_list(payload.get("threat_actors")),
        "blast_radius": trim_to_one_sentence(str(payload.get("blast_radius", "")), ensure_terminal_period=True),
        "mitigations_present": normalize_string_list(payload.get("mitigations_present")),
        "mitigations_absent": normalize_string_list(payload.get("mitigations_absent")),
        "domain_risks": normalize_string_list(payload.get("domain_risks")),
    }


def render_inline_list(values: list[str], fallback: str) -> str:
    return ", ".join(values) if values else fallback


def render_entry_points(entry_points: list[dict[str, Any]]) -> str:
    if not entry_points:
        return "0 — none identified in changed code."
    rendered = "; ".join(
        f"`{item['file']}:{item['line']}` {escape_pipes(item['description'])}"
        for item in entry_points
    )
    return f"{len(entry_points)} — {rendered}"


def build_threat_model_comment(payload: dict[str, Any]) -> str:
    normalized = normalize_threat_model_payload(payload)
    if not normalized.get("generated"):
        return ""

    lines = [
        THREAT_MODEL_COMMENT_MARKER,
        "## Threat Model",
        "",
        f"**Blast radius:** {normalized['blast_radius'] or 'Unable to determine from the supplied PR artifacts.'}",
        "",
        f"**Entry points added:** {render_entry_points(normalized['entry_points_added'])}",
        f"**Assets at risk:** {render_inline_list(normalized['assets_at_risk'], 'none identified')}",
        f"**Relevant threat actors:** {render_inline_list(normalized['threat_actors'], 'none identified')}",
        "",
        "<details>",
        "<summary>Mitigations</summary>",
        "",
        f"Present: {render_inline_list(normalized['mitigations_present'], 'none noted')}",
        f"Absent: {render_inline_list(normalized['mitigations_absent'], 'none noted')}",
        "",
        "</details>",
    ]

    if normalized["domain_risks"]:
        lines.extend(
            [
                "",
                "<details>",
                "<summary>Domain risks</summary>",
                "",
                *[f"- {risk}" for risk in normalized["domain_risks"]],
                "",
                "</details>",
            ]
        )

    lines.extend(["", "> Advisory only — does not affect gate decision."])
    return "\n".join(lines)


def upsert_marked_comment(repo_name: str, pr_number: int, token: str, body: str, marker: str) -> None:
    from github import Github

    client = Github(token)
    repo = client.get_repo(repo_name)
    pull_request = repo.get_pull(pr_number)

    for comment in pull_request.get_issue_comments():
        if marker in comment.body:
            comment.edit(body)
            return

    pull_request.create_issue_comment(body)


def upsert_comment(repo_name: str, pr_number: int, token: str, body: str) -> None:
    upsert_marked_comment(repo_name, pr_number, token, body, COMMENT_MARKER)


def render_comment(payload: dict[str, Any], has_critical: bool | None = None) -> str:
    return build_comment_body(normalize_payload(payload, has_critical=has_critical))


def build_combined_output(main_body: str, threat_model_body: str) -> str:
    if not threat_model_body:
        return main_body
    return f"{main_body}\n\n{threat_model_body}"


def load_optional_json_object(path: str) -> dict[str, Any] | None:
    json_path = Path(path)
    if not json_path.exists():
        return None
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else None


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    payload = normalize_payload(payload)
    body = build_comment_body(payload)
    threat_model_body = ""

    if args.threat_model:
        threat_model_payload = load_optional_json_object(args.threat_model)
        if threat_model_payload is not None:
            threat_model_body = build_threat_model_comment(threat_model_payload)
    combined_output = build_combined_output(body, threat_model_body)

    if args.output:
        Path(args.output).write_text(combined_output, encoding="utf-8")

    if args.dry_run:
        print(combined_output)
        return 1 if payload["summary"]["has_critical"] else 0

    token = os.getenv("GITHUB_TOKEN")
    repo_name = os.getenv("GITHUB_REPOSITORY")
    pr_number = os.getenv("PR_NUMBER")

    if not token or not repo_name or not pr_number:
        raise SystemExit("GITHUB_TOKEN, GITHUB_REPOSITORY, and PR_NUMBER must be set unless --dry-run is used.")

    upsert_comment(repo_name, int(pr_number), token, body)
    if threat_model_body:
        upsert_marked_comment(
            repo_name,
            int(pr_number),
            token,
            threat_model_body,
            THREAT_MODEL_COMMENT_MARKER,
        )

    return 1 if payload["summary"]["has_critical"] else 0


if __name__ == "__main__":
    sys.exit(main())
