#!/usr/bin/env python3
"""Run Semgrep against files changed in a pull request."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
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
        "--rules",
        required=True,
        help="Path to the Semgrep rules file.",
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
    diff_range = f"{base_sha}...{head_sha}"
    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", diff_range],
        check=True,
        capture_output=True,
        text=True,
    )
    files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return files


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


def empty_results(reason: str, changed_files: list[str]) -> dict[str, Any]:
    return {
        "results": [],
        "errors": [],
        "paths": {
            "scanned": [],
            "changed": changed_files,
        },
        "metadata": {
            "reason": reason,
            "scanner": "semgrep",
        },
    }


def run_semgrep(rules_path: str, files: list[str]) -> dict[str, Any]:
    command = [
        "semgrep",
        "scan",
        "--config",
        rules_path,
        "--json",
        "--quiet",
        "--error",
        *files,
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if result.returncode not in (0, 1):
        raise RuntimeError(
            "Semgrep execution failed.\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    payload = json.loads(result.stdout or "{}")
    payload.setdefault("results", [])
    payload.setdefault("errors", [])
    payload.setdefault("paths", {})
    payload["paths"]["scanned"] = files
    return payload


def main() -> int:
    args = parse_args()

    if not args.base_sha or not args.head_sha:
        raise SystemExit(
            "Both --base-sha and --head-sha are required. "
            "Set GITHUB_BASE_SHA and GITHUB_HEAD_SHA in CI or pass them explicitly."
        )

    changed_files = run_git_diff(args.base_sha, args.head_sha)
    scannable_files = filter_scannable_files(changed_files)

    if not changed_files:
        payload = empty_results("No changed files detected in diff.", changed_files)
    elif not scannable_files:
        payload = empty_results("No changed files matched supported source extensions.", changed_files)
    else:
        payload = run_semgrep(args.rules, scannable_files)
        payload.setdefault("metadata", {})
        payload["metadata"]["reason"] = "Scan completed."
        payload["metadata"]["scanner"] = "semgrep"
        payload["paths"]["changed"] = changed_files

    output_path = Path(args.output)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
