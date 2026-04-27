"""Load and safely render AI prompt templates from TOML files."""

from __future__ import annotations

import string
import tomllib
from pathlib import Path
from typing import Any


PROMPT_DIR = Path(__file__).resolve().parents[1] / "prompts"
MAX_INJECT_BYTES = 24000
ALLOWED_VARIABLES = {
    "narrative": {
        "github_repository",
        "pr_title",
        "pr_branch",
        "critical",
        "high",
        "medium",
        "low",
        "scanned_files",
        "changed_files",
        "domain_summary",
        "highest_severity",
        "highest_severity_count",
        "priority_file",
        "findings_block",
    },
    "domain_context": {"files_block"},
    "enrich": {"domain_summary", "findings_block"},
    "terrain": {"domain_summary", "file_path", "file_findings", "file_content"},
    "adversarial": {"domain_summary", "finding_block"},
    "call_graph": {"domain_summary", "max_depth", "changed_function_block", "chain_block"},
}
_PROMPT_CACHE: dict[str, dict[str, Any]] = {}


def load(name: str) -> dict[str, Any]:
    cached = _PROMPT_CACHE.get(name)
    if cached is not None:
        return cached

    path = PROMPT_DIR / f"{name}.toml"
    with path.open("rb") as handle:
        prompt = tomllib.load(handle)

    validate_prompt(name, prompt)
    _PROMPT_CACHE[name] = prompt
    return prompt


def render(name: str, template_name: str, **kwargs: Any) -> str:
    prompt = load(name)
    template = prompt[template_name]["content"]
    allowed = ALLOWED_VARIABLES.get(name, set())
    unexpected = sorted(set(kwargs) - allowed)
    if unexpected:
        raise ValueError(
            f"Unexpected prompt variables for {name}: {', '.join(unexpected)}"
        )

    field_names = extract_field_names(template)
    missing = sorted(field_names - set(kwargs))
    if missing:
        raise ValueError(f"Missing prompt variables for {name}: {', '.join(missing)}")

    parts: list[str] = []
    formatter = string.Formatter()
    for literal_text, field_name, format_spec, conversion in formatter.parse(template):
        parts.append(literal_text)
        if field_name is None:
            continue
        if format_spec or conversion:
            raise ValueError(f"Unsupported format modifier in {name}.{template_name}")
        parts.append(sanitize_value(kwargs[field_name]))
    return "".join(parts)


def render_prompt(name: str, variables: dict[str, Any] | None = None) -> dict[str, str]:
    values = dict(variables or {})
    return {
        "system": render(name, "system", **values),
        "user": render(name, "user_template", **values),
    }


def validate_prompt(name: str, prompt: dict[str, Any]) -> None:
    meta = prompt.get("meta")
    if not isinstance(meta, dict):
        raise ValueError(f"Prompt {name} is missing [meta]")

    for section_name in ("system", "user_template"):
        section = prompt.get(section_name)
        if not isinstance(section, dict):
            raise ValueError(f"Prompt {name} is missing [{section_name}]")
        content = section.get("content")
        if not isinstance(content, str):
            raise ValueError(f"Prompt {name} section [{section_name}] must define string content")

    allowed = ALLOWED_VARIABLES.get(name)
    if allowed is None:
        raise ValueError(f"No allowlist configured for prompt {name}")

    for template_name in ("system", "user_template"):
        field_names = extract_field_names(prompt[template_name]["content"])
        disallowed = sorted(field_names - allowed)
        if disallowed:
            raise ValueError(
                f"Prompt {name}.{template_name} uses undeclared variables: {', '.join(disallowed)}"
            )


def extract_field_names(template: str) -> set[str]:
    field_names: set[str] = set()
    formatter = string.Formatter()
    for _, field_name, format_spec, conversion in formatter.parse(template):
        if field_name is None:
            continue
        if format_spec or conversion:
            raise ValueError("Prompt templates may not use format specifiers or conversions")
        field_names.add(field_name)
    return field_names


def sanitize_value(value: Any) -> str:
    text = "unknown" if value is None else str(value)
    cleaned = "".join(
        character
        for character in text
        if character in ("\n", "\t") or character.isprintable()
    ).replace("\r", "")

    encoded = cleaned.encode("utf-8", errors="ignore")
    if len(encoded) <= MAX_INJECT_BYTES:
        return cleaned
    return encoded[:MAX_INJECT_BYTES].decode("utf-8", errors="ignore")
