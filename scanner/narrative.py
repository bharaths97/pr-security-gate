#!/usr/bin/env python3
"""Generate an optional AI risk narrative from triaged findings."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages"
OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_VERSION = "2023-06-01"
REQUEST_TIMEOUT_SECONDS = 30
MAX_PROMPT_FINDINGS = 25
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"
DEFAULT_OPENAI_MODEL = "gpt-4o"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Triaged findings JSON path.")
    parser.add_argument("--output", required=True, help="Narrative findings JSON path.")
    return parser.parse_args()


def select_provider() -> dict[str, str] | None:
    provider_preference = os.getenv("AI_PROVIDER", "auto").strip().lower()
    if provider_preference in ("", "auto"):
        return select_first_available_provider()
    if provider_preference in ("none", "disabled", "off"):
        return None
    if provider_preference == "anthropic":
        return select_anthropic_provider()
    if provider_preference == "openai":
        return select_openai_provider()

    return None


def select_first_available_provider() -> dict[str, str] | None:
    return select_anthropic_provider() or select_openai_provider()


def select_anthropic_provider() -> dict[str, str] | None:
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if anthropic_key:
        return {
            "name": "anthropic",
            "api_key": anthropic_key,
            "model": os.getenv("ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL),
        }
    return None


def select_openai_provider() -> dict[str, str] | None:
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        return {
            "name": "openai",
            "api_key": openai_key,
            "model": os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL),
        }
    return None


def build_output_payload(payload: dict[str, Any], narrative: str | None) -> dict[str, Any]:
    output = dict(payload)
    output["narrative"] = narrative
    return output


def build_system_prompt() -> str:
    return (
        "You are generating a concise security summary for a pull request based ONLY on the provided scan results. "
        "Do not infer or invent issues beyond the input. "
        "Write 2–4 sentences in plain English for a human reviewer, focusing on overall security risk and impact rather than listing individual findings. "
        "If issues are present, briefly characterize severity (e.g., low, moderate, high) and highlight the most important remediation priority if one clearly stands out. "
        "If no meaningful security issues are found, explicitly state that the changes appear low risk. "
        "Avoid hype, speculation, and unnecessary detail. Do not use markdown, bullets, or headings."
    )


def build_user_prompt(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    counts = summary.get("counts", {})
    source = payload.get("source", {})
    findings = payload.get("findings", [])
    prompt_findings = findings[:MAX_PROMPT_FINDINGS]

    metadata_lines = [
        f"Repository: {os.getenv('GITHUB_REPOSITORY', 'unknown')}",
        f"PR title: {os.getenv('PR_TITLE', 'unknown')}",
        f"PR branch: {os.getenv('PR_BRANCH', 'unknown')}",
        (
            "Summary counts: "
            f"critical={counts.get('critical', 0)}, "
            f"high={counts.get('high', 0)}, "
            f"medium={counts.get('medium', 0)}, "
            f"low={counts.get('low', 0)}"
        ),
        f"Scanned files: {len(source.get('scanned_files', []))}",
        f"Changed files: {len(source.get('changed_files', []))}",
        "",
        "Findings:",
    ]

    for finding in prompt_findings:
        metadata_lines.append(
            "- {severity} | {file}:{line} | {message} | CWE: {cwe} | Suggested fix: {fix}".format(
                severity=str(finding.get("severity", "unknown")).upper(),
                file=finding.get("file", ""),
                line=finding.get("line", ""),
                message=one_line_text(finding.get("finding", "")),
                cwe=one_line_text(finding.get("cwe", "N/A")),
                fix=one_line_text(finding.get("fix_suggestion", "")),
            )
        )

    if len(findings) > len(prompt_findings):
        metadata_lines.append(
            f"- Additional findings omitted from prompt for brevity: {len(findings) - len(prompt_findings)}"
        )

    metadata_lines.extend(
        [
            "",
            "Return only the reviewer-facing summary text.",
        ]
    )
    return "\n".join(metadata_lines)


def one_line_text(value: Any) -> str:
    return " ".join(str(value).split())


def request_json(url: str, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def extract_anthropic_text(response_payload: dict[str, Any]) -> str:
    content = response_payload.get("content", [])
    parts = [
        item.get("text", "").strip()
        for item in content
        if isinstance(item, dict) and item.get("type") == "text" and item.get("text")
    ]
    return "\n".join(parts).strip()


def extract_openai_text(response_payload: dict[str, Any]) -> str:
    choices = response_payload.get("choices", [])
    for choice in choices:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message", {})
        text = message.get("content")
        if isinstance(text, str) and text.strip():
            return text.strip()
    return ""


def generate_with_anthropic(payload: dict[str, Any], api_key: str, model: str) -> str:
    response_payload = request_json(
        ANTHROPIC_ENDPOINT,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "Anthropic-Version": ANTHROPIC_VERSION,
        },
        body={
            "model": model,
            "max_tokens": 220,
            "temperature": 0.2,
            "system": build_system_prompt(),
            "messages": [
                {
                    "role": "user",
                    "content": build_user_prompt(payload),
                }
            ],
        },
    )
    return extract_anthropic_text(response_payload)


def generate_with_openai(payload: dict[str, Any], api_key: str, model: str) -> str:
    response_payload = request_json(
        OPENAI_ENDPOINT,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        body={
            "model": model,
            "messages": [
                {"role": "system", "content": build_system_prompt()},
                {"role": "user", "content": build_user_prompt(payload)},
            ],
        },
    )
    return extract_openai_text(response_payload)


def generate_narrative(payload: dict[str, Any], provider: dict[str, str]) -> str:
    if provider["name"] == "anthropic":
        text = generate_with_anthropic(payload, provider["api_key"], provider["model"])
    elif provider["name"] == "openai":
        text = generate_with_openai(payload, provider["api_key"], provider["model"])
    else:
        raise ValueError(f"Unsupported provider: {provider['name']}")

    cleaned = one_line_text(text)
    if not cleaned:
        raise RuntimeError("Provider returned an empty narrative.")
    return cleaned


def enrich_payload(payload: dict[str, Any]) -> dict[str, Any]:
    findings = payload.get("findings", [])
    if not findings:
        return build_output_payload(payload, None)

    provider = select_provider()
    if provider is None:
        return build_output_payload(payload, None)

    try:
        narrative = generate_narrative(payload, provider)
    except Exception as exc:
        print(f"Warning: narrative generation failed ({provider['name']}): {exc}", file=sys.stderr)
        narrative = None

    return build_output_payload(payload, narrative)


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    output = enrich_payload(payload)
    Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
