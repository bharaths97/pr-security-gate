"""Shared AI provider selection and text generation helpers."""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any


ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages"
OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_VERSION = "2023-06-01"
REQUEST_TIMEOUT_SECONDS = 30
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"
DEFAULT_OPENAI_MODEL = "gpt-4o"


def select_provider() -> dict[str, str] | None:
    provider_preference = os.getenv("AI_PROVIDER", "auto").strip().lower()
    if provider_preference in ("", "auto"):
        return select_anthropic_provider() or select_openai_provider()
    if provider_preference in ("none", "disabled", "off"):
        return None
    if provider_preference == "anthropic":
        return select_anthropic_provider()
    if provider_preference == "openai":
        return select_openai_provider()
    return None


def select_anthropic_provider() -> dict[str, str] | None:
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if not anthropic_key:
        return None
    return {
        "name": "anthropic",
        "api_key": anthropic_key,
        "model": os.getenv("ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL),
    }


def select_openai_provider() -> dict[str, str] | None:
    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        return None
    return {
        "name": "openai",
        "api_key": openai_key,
        "model": os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL),
    }


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


def generate_text(system_prompt: str, user_prompt: str, provider: dict[str, str], max_tokens: int = 600) -> str:
    if provider["name"] == "anthropic":
        return generate_with_anthropic(system_prompt, user_prompt, provider["api_key"], provider["model"], max_tokens)
    if provider["name"] == "openai":
        return generate_with_openai(system_prompt, user_prompt, provider["api_key"], provider["model"])
    raise ValueError(f"Unsupported provider: {provider['name']}")


def generate_with_anthropic(
    system_prompt: str,
    user_prompt: str,
    api_key: str,
    model: str,
    max_tokens: int,
) -> str:
    response_payload = request_json(
        ANTHROPIC_ENDPOINT,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "Anthropic-Version": ANTHROPIC_VERSION,
        },
        body={
            "model": model,
            "max_tokens": max_tokens,
            "temperature": 0.2,
            "system": system_prompt,
            "messages": [
                {
                    "role": "user",
                    "content": user_prompt,
                }
            ],
        },
    )
    return extract_anthropic_text(response_payload)


def generate_with_openai(system_prompt: str, user_prompt: str, api_key: str, model: str) -> str:
    response_payload = request_json(
        OPENAI_ENDPOINT,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        body={
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        },
    )
    return extract_openai_text(response_payload)
