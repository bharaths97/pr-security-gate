# Prompt Schema

All prompt files in this directory use the same TOML shape:

```toml
[meta]
phase = 1
version = 1
purpose = "Short explanation of what the prompt does."

[system]
content = """
System prompt text.
"""

[user_template]
content = """
User prompt template with placeholders like {example_value}.
"""
```

Conventions:

- Use only `meta`, `system`, and `user_template` sections.
- `system.content` and `user_template.content` must be multiline strings.
- Variables use `{name}` placeholders.
- Substitution happens through `scanner/prompt_loader.py`, not raw `.format()`.
- Add new placeholders only when the matching allowlist in `scanner/prompt_loader.py` is updated.
