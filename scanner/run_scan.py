#!/usr/bin/env python3
"""Run Semgrep against files changed in a pull request."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("local", "cloud"),
        default="local",
        help="Scanning backend to use. Defaults to local custom rules.",
    )
    parser.add_argument(
        "--rules",
        help="Path to the Semgrep rules directory or file for local mode.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path where the Semgrep JSON results will be written.",
    )
    parser.add_argument(
        "--base-sha",
        default=os.getenv("GITHUB_BASE_SHA"),
        help="Base commit SHA for the pull request diff.",
    )
    parser.add_argument(
        "--head-sha",
        default=os.getenv("GITHUB_HEAD_SHA"),
        help="Head commit SHA for the pull request diff.",
    )
    return parser.parse_args()


def run_git_diff(base_sha: str, head_sha: str) -> list[str]:
    diff_range = f"{base_sha}..{head_sha}"
    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", diff_range],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def filter_scannable_files(files: list[str]) -> list[str]:
    filtered: list[str] = []
    for file_path in files:
        path = Path(file_path)
        if not path.exists():
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        filtered.append(str(path))
    return filtered


def empty_results(
    reason: str,
    changed_files: list[str],
    scanned_files: list[str],
    scanner: str,
    base_sha: str | None,
    head_sha: str | None,
) -> dict[str, Any]:
    return {
        "results": [],
        "errors": [],
        "paths": {
            "scanned": scanned_files,
            "changed": changed_files,
        },
        "metadata": {
            "reason": reason,
            "scanner": scanner,
            "base_sha": base_sha or "",
            "head_sha": head_sha or "",
        },
    }


def build_local_command(rules_path: str, files: list[str]) -> list[str]:
    return [
        "semgrep",
        "scan",
        "--config",
        rules_path,
        "--json",
        "--quiet",
        "--error",
        *files,
    ]


def build_cloud_command(base_sha: str, json_output_path: Path) -> list[str]:
    return [
        "semgrep",
        "ci",
        "--baseline-commit",
        base_sha,
        "--json-output",
        str(json_output_path),
    ]


def normalize_scan_payload(
    payload: dict[str, Any],
    *,
    changed_files: list[str],
    scanned_files: list[str],
    scanner: str,
    reason: str,
    base_sha: str | None,
    head_sha: str | None,
) -> dict[str, Any]:
    payload.setdefault("results", [])
    payload.setdefault("errors", [])
    payload.setdefault("paths", {})
    payload.setdefault("metadata", {})
    payload["paths"]["changed"] = changed_files
    payload["paths"]["scanned"] = scanned_files
    payload["metadata"]["reason"] = reason
    payload["metadata"]["scanner"] = scanner
    payload["metadata"]["base_sha"] = base_sha or ""
    payload["metadata"]["head_sha"] = head_sha or ""
    return payload


def run_local_scan(
    rules_path: str | None,
    files: list[str],
    changed_files: list[str],
    base_sha: str | None,
    head_sha: str | None,
) -> dict[str, Any]:
    if not rules_path:
        raise SystemExit("--rules is required when --mode local is used.")

    result = subprocess.run(
        build_local_command(rules_path, files),
        capture_output=True,
        text=True,
    )

    if result.returncode not in (0, 1):
        raise RuntimeError(
            "Semgrep local scan failed.\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    payload = json.loads(result.stdout or "{}")
    return normalize_scan_payload(
        payload,
        changed_files=changed_files,
        scanned_files=files,
        scanner="semgrep",
        reason="Scan completed.",
        base_sha=base_sha,
        head_sha=head_sha,
    )


def run_cloud_scan(base_sha: str, head_sha: str | None, changed_files: list[str]) -> dict[str, Any]:
    if not os.getenv("SEMGREP_APP_TOKEN"):
        raise SystemExit("SEMGREP_APP_TOKEN must be set when --mode cloud is used.")

    with tempfile.TemporaryDirectory() as temp_dir:
        output_path = Path(temp_dir) / "semgrep-ci.json"
        result = subprocess.run(
            build_cloud_command(base_sha, output_path),
            capture_output=True,
            text=True,
        )

        if result.returncode not in (0, 1):
            raise RuntimeError(
                "Semgrep cloud scan failed.\n"
                f"STDOUT:\n{result.stdout}\n"
                f"STDERR:\n{result.stderr}"
            )

        payload_text = output_path.read_text(encoding="utf-8") if output_path.exists() else "{}"
        payload = json.loads(payload_text or "{}")

    return normalize_scan_payload(
        payload,
        changed_files=changed_files,
        scanned_files=[],
        scanner="semgrep-cloud",
        reason="Scan completed.",
        base_sha=base_sha,
        head_sha=head_sha,
    )


def main() -> int:
    args = parse_args()

    if not args.base_sha or not args.head_sha:
        raise SystemExit(
            "Both --base-sha and --head-sha are required. "
            "Set GITHUB_BASE_SHA and GITHUB_HEAD_SHA in CI or pass them explicitly."
        )

    changed_files = run_git_diff(args.base_sha, args.head_sha)
    scannable_files = filter_scannable_files(changed_files)
    scanner_name = "semgrep-cloud" if args.mode == "cloud" else "semgrep"

    if not changed_files:
        payload = empty_results("No changed files detected in diff.", changed_files, [], scanner_name, args.base_sha, args.head_sha)
    elif not scannable_files:
        payload = empty_results(
            "No changed files matched supported source extensions.",
            changed_files,
            [],
            scanner_name,
            args.base_sha,
            args.head_sha,
        )
    elif args.mode == "cloud":
        payload = run_cloud_scan(args.base_sha, args.head_sha, changed_files)
    else:
        payload = run_local_scan(args.rules, scannable_files, changed_files, args.base_sha, args.head_sha)

    output_path = Path(args.output)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
