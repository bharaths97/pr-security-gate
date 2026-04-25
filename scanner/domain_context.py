#!/usr/bin/env python3
"""Generate optional repository domain context for later AI phases."""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from scanner import ai_provider, prompt_loader


MAX_CONTEXT_BYTES = 24000
DOMAIN_CONTEXT_SCHEMA_VERSION = 1
ALLOWED_EXACT_FILES = {
    ".env.example",
    "Dockerfile",
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
    "go.mod",
    "package.json",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "Cargo.toml",
}
ALLOWED_PATTERNS = (
    "README*",
    "requirements*.txt",
    "*.example",
    "*.sample",
    "*.yaml",
    "*.yml",
    "*.toml",
    "*.json",
)
DENIED_EXACT_FILES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "comment-preview.md",
    "domain_context.json",
    "narrative-findings.json",
    "scan-results.json",
    "triaged-findings.json",
}
DENIED_PREFIXES = (".git", ".pr-security-gate", ".venv", "node_modules", "__pycache__")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".", help="Repository root to inspect.")
    parser.add_argument("--output", required=True, help="Domain context JSON path.")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=MAX_CONTEXT_BYTES,
        help="Maximum total bytes of context sent to the AI provider.",
    )
    return parser.parse_args()


def is_allowed_context_file(path: Path) -> bool:
    name = path.name
    if name in DENIED_EXACT_FILES:
        return False
    if any(part.startswith(DENIED_PREFIXES) for part in path.parts):
        return False
    if name in ALLOWED_EXACT_FILES:
        return True
    return any(fnmatch.fnmatch(name, pattern) for pattern in ALLOWED_PATTERNS)


def collect_context_files(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for path in repo_root.iterdir():
        if not path.is_file():
            continue
        relative_path = path.relative_to(repo_root)
        if is_allowed_context_file(relative_path):
            files.append(path)
    return sorted(files, key=lambda item: item.name.lower())


def read_context(files: list[Path], repo_root: Path, max_bytes: int) -> list[dict[str, str]]:
    remaining = max_bytes
    context: list[dict[str, str]] = []
    for path in files:
        if remaining <= 0:
            break
        text = path.read_text(encoding="utf-8", errors="replace")
        snippet = text[:remaining]
        remaining -= len(snippet.encode("utf-8", errors="replace"))
        context.append(
            {
                "path": str(path.relative_to(repo_root)),
                "content": snippet,
            }
        )
    return context


def unknown_context(reason: str, files_considered: list[str] | None = None) -> dict[str, Any]:
    return {
        "schema_version": DOMAIN_CONTEXT_SCHEMA_VERSION,
        "generated": False,
        "reason": reason,
        "app_domain": "unknown",
        "data_sensitivity": "unknown",
        "regulatory_context": [],
        "user_types": [],
        "deployment": "unknown",
        "risk_tier": "unknown",
        "source_files": files_considered or [],
    }


def build_system_prompt() -> str:
    return prompt_loader.render("domain_context", "system")


def build_user_prompt(context_files: list[dict[str, str]]) -> str:
    return prompt_loader.render(
        "domain_context",
        "user_template",
        files_block=json.dumps(context_files, indent=2),
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
        raise ValueError("Domain context response must be a JSON object.")
    return parsed


def normalize_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def normalize_context(parsed: dict[str, Any], source_files: list[str]) -> dict[str, Any]:
    return {
        "schema_version": DOMAIN_CONTEXT_SCHEMA_VERSION,
        "generated": True,
        "reason": "generated",
        "app_domain": str(parsed.get("app_domain") or "unknown"),
        "data_sensitivity": str(parsed.get("data_sensitivity") or "unknown"),
        "regulatory_context": normalize_list(parsed.get("regulatory_context")),
        "user_types": normalize_list(parsed.get("user_types")),
        "deployment": str(parsed.get("deployment") or "unknown"),
        "risk_tier": str(parsed.get("risk_tier") or "unknown"),
        "source_files": source_files,
    }


def generate_domain_context(repo_root: Path, max_bytes: int = MAX_CONTEXT_BYTES) -> dict[str, Any]:
    files = collect_context_files(repo_root)
    source_files = [str(path.relative_to(repo_root)) for path in files]
    if not files:
        return unknown_context("no_context_files", source_files)

    provider = ai_provider.select_provider()
    if provider is None:
        return unknown_context("no_provider", source_files)

    try:
        context_files = read_context(files, repo_root, max_bytes)
        response = ai_provider.generate_text(
            build_system_prompt(),
            build_user_prompt(context_files),
            provider,
            max_tokens=700,
        )
        parsed = parse_json_object(response)
        return normalize_context(parsed, source_files)
    except Exception as exc:
        print(f"Warning: domain context generation failed ({provider['name']}): {exc}", file=sys.stderr)
        return unknown_context("provider_failed", source_files)


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    output = generate_domain_context(repo_root, args.max_bytes)
    Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
