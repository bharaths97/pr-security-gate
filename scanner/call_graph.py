#!/usr/bin/env python3
"""Optionally append low-confidence cross-file call-chain observations."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.append(str(Path(__file__).resolve().parents[1]))

from scanner import ai_provider, prompt_loader


SUPPORTED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}
PYTHON_EXTENSIONS = {".py"}
JAVASCRIPT_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
MAX_RESPONSE_TOKENS = 900
DEFAULT_MAX_DEPTH = 2
MAX_INDEX_FILE_BYTES = 120_000
CALL_RE = re.compile(r"\b([A-Za-z_][$\w]*(?:\.[A-Za-z_][$\w]*)?)\s*\(")
PYTHON_FUNCTION_RE = re.compile(r"^(?P<indent>\s*)(?:async\s+def|def)\s+(?P<name>[A-Za-z_]\w*)\s*\(")
JS_FUNCTION_RE = re.compile(
    r"^(?:\s*export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\("
)
JS_ARROW_RE = re.compile(
    r"^(?:\s*export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{"
)
PYTHON_FROM_IMPORT_RE = re.compile(r"^\s*from\s+([.\w]+)\s+import\s+(.+)$")
PYTHON_IMPORT_RE = re.compile(r"^\s*import\s+([.\w]+)(?:\s+as\s+([A-Za-z_]\w*))?\s*$")
JS_IMPORT_RE = re.compile(r"^\s*import\s+(.+?)\s+from\s+['\"]([^'\"]+)['\"]\s*;?\s*$")
JS_REQUIRE_RE = re.compile(
    r"^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)\s*;?\s*$"
)
KEYWORD_CALLS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "typeof",
    "await",
    "new",
    "super",
    "import",
}
SINK_MATCHERS = [
    (
        re.compile(r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\("),
        "subprocess shell or process execution",
    ),
    (re.compile(r"\bos\.system\s*\("), "os.system shell execution"),
    (re.compile(r"\b(?:cursor|db|connection)\.execute\s*\("), "database query execution"),
    (re.compile(r"\b(?:eval|exec)\s*\("), "dynamic code execution"),
    (re.compile(r"\b(?:open|Path\(.+?\)\.write_text|Path\(.+?\)\.write_bytes)\s*\("), "file write or file-system access"),
    (re.compile(r"\bpickle\.loads\s*\("), "unsafe deserialization"),
    (re.compile(r"\brender_template_string\s*\("), "HTML rendering"),
    (re.compile(r"\byaml\.load\s*\("), "unsafe YAML deserialization"),
    (re.compile(r"\b(?:exec|execSync|spawn|spawnSync)\s*\("), "child process execution"),
    (re.compile(r"\b(?:db|pool|client|connection)\.query\s*\("), "database query execution"),
    (re.compile(r"\beval\s*\("), "dynamic JavaScript execution"),
    (re.compile(r"\binnerHTML\s*="), "HTML rendering"),
    (re.compile(r"\bdocument\.write\s*\("), "HTML rendering"),
    (re.compile(r"\bfs\.(?:writeFile|appendFile|writeFileSync|appendFileSync)\s*\("), "file write"),
]
select_provider = ai_provider.select_provider


@dataclass(frozen=True)
class FunctionDef:
    name: str
    file_path: str
    start_line: int
    end_line: int
    body: str
    language: str

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.file_path, self.name, self.start_line)


@dataclass(frozen=True)
class ImportTarget:
    file_path: str
    symbol: str | None = None


@dataclass(frozen=True)
class ResolvedCall:
    function: FunctionDef
    call_name: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Verified findings JSON path.")
    parser.add_argument("--output", required=True, help="Call-graph findings JSON path.")
    parser.add_argument(
        "--context",
        help="Optional domain context JSON path.",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root used to read changed files and same-repo callees.",
    )
    parser.add_argument(
        "--base-sha",
        default=os.getenv("GITHUB_BASE_SHA"),
        help="Optional base commit SHA. Falls back to input JSON metadata or GITHUB_BASE_SHA.",
    )
    parser.add_argument(
        "--head-sha",
        default=os.getenv("GITHUB_HEAD_SHA"),
        help="Optional head commit SHA. Falls back to input JSON metadata or GITHUB_HEAD_SHA.",
    )
    return parser.parse_args()


def build_output_payload(
    payload: dict[str, Any],
    findings: list[dict[str, Any]],
    cross_file_chains: int | None = None,
) -> dict[str, Any]:
    output = dict(payload)
    output["findings"] = findings
    if cross_file_chains is None:
        return output

    summary = dict(output.get("summary", {}))
    summary["total"] = len(findings)
    summary["cross_file_chains"] = cross_file_chains
    output["summary"] = summary
    return output


def build_system_prompt() -> str:
    return prompt_loader.render("call_graph", "system")


def load_domain_context(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None

    context_path = Path(path)
    if not context_path.exists():
        return None

    try:
        loaded = json.loads(context_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Warning: unable to load domain context ({context_path}): {exc}", file=sys.stderr)
        return None

    return loaded if isinstance(loaded, dict) else None


def build_domain_summary(domain_context: dict[str, Any] | None) -> str:
    if not isinstance(domain_context, dict) or not domain_context.get("generated"):
        return "unknown"

    return "; ".join(
        [
            f"app_domain={one_line_text(domain_context.get('app_domain', 'unknown'))}",
            f"data_sensitivity={one_line_text(domain_context.get('data_sensitivity', 'unknown'))}",
            f"regulatory_context={join_values(domain_context.get('regulatory_context'))}",
            f"user_types={join_values(domain_context.get('user_types'))}",
            f"deployment={one_line_text(domain_context.get('deployment', 'unknown'))}",
            f"risk_tier={one_line_text(domain_context.get('risk_tier', 'unknown'))}",
        ]
    )


def join_values(value: Any) -> str:
    if not isinstance(value, list):
        return "unknown"
    cleaned = [one_line_text(item) for item in value if one_line_text(item)]
    return ", ".join(cleaned) if cleaned else "unknown"


def one_line_text(value: Any) -> str:
    return " ".join(str(value).split())


def format_numbered_block(function: FunctionDef) -> str:
    numbered = [
        f"{function.start_line + index:4}: {line}"
        for index, line in enumerate(function.body.splitlines())
    ]
    return "\n".join(numbered)


def build_changed_function_block(function: FunctionDef) -> str:
    return json.dumps(
        {
            "name": function.name,
            "file": function.file_path,
            "start_line": function.start_line,
            "end_line": function.end_line,
            "language": function.language,
            "code": format_numbered_block(function),
        },
        indent=2,
    )


def build_chain_block(functions: list[FunctionDef], sink_description: str) -> str:
    chain_payload = {
        "functions": [
            {
                "name": function.name,
                "file": function.file_path,
                "start_line": function.start_line,
                "end_line": function.end_line,
                "language": function.language,
                "code": format_numbered_block(function),
            }
            for function in functions
        ],
        "static_sink_hint": sink_description,
    }
    return json.dumps(chain_payload, indent=2)


def build_user_prompt(
    root_function: FunctionDef,
    chain_functions: list[FunctionDef],
    sink_description: str,
    max_depth: int,
    domain_context: dict[str, Any] | None,
) -> str:
    return prompt_loader.render(
        "call_graph",
        "user_template",
        domain_summary=build_domain_summary(domain_context),
        max_depth=max_depth,
        changed_function_block=build_changed_function_block(root_function),
        chain_block=build_chain_block(chain_functions, sink_description),
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
        raise ValueError("Call graph response must be a JSON object.")
    return parsed


def normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = one_line_text(value)
    if not cleaned or cleaned.lower() in {"unknown", "none", "null"}:
        return None
    return cleaned


def normalize_chain_response(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("Call graph response must be a JSON object.")

    reaches_sink = item.get("reaches_sink")
    if not isinstance(reaches_sink, bool):
        raise ValueError("Call graph response must define boolean reaches_sink.")

    normalized: dict[str, Any] = {"reaches_sink": reaches_sink}
    chain = normalize_optional_text(item.get("chain"))
    if chain is not None:
        normalized["chain"] = chain
    sink_description = normalize_optional_text(item.get("sink_description"))
    if sink_description is not None:
        normalized["sink_description"] = sink_description
    return normalized


def resolve_diff_range(
    payload: dict[str, Any],
    base_sha: str | None,
    head_sha: str | None,
) -> tuple[str | None, str | None]:
    source = payload.get("source", {})
    resolved_base = base_sha or source.get("base_sha")
    resolved_head = head_sha or source.get("head_sha")
    return resolved_base or None, resolved_head or None


def collect_added_lines(repo_root: Path, file_path: str, base_sha: str | None, head_sha: str | None) -> set[int] | None:
    if not base_sha or not head_sha:
        return None

    import subprocess

    result = subprocess.run(
        ["git", "diff", "--unified=0", f"{base_sha}..{head_sha}", "--", file_path],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )

    added_lines: set[int] = set()
    for line in result.stdout.splitlines():
        match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
        if not match:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or "1")
        for line_number in range(start, start + count):
            added_lines.add(line_number)
    return added_lines


def detect_language(file_path: str) -> str | None:
    suffix = Path(file_path).suffix.lower()
    if suffix in PYTHON_EXTENSIONS:
        return "python"
    if suffix in JAVASCRIPT_EXTENSIONS:
        return "javascript"
    return None


def read_text_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    if path.stat().st_size > MAX_INDEX_FILE_BYTES:
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def parse_python_functions(file_path: str, content: str) -> list[FunctionDef]:
    lines = content.splitlines()
    functions: list[FunctionDef] = []

    for index, line in enumerate(lines, start=1):
        match = PYTHON_FUNCTION_RE.match(line)
        if not match:
            continue
        indent = len(match.group("indent"))
        end_line = len(lines)
        for scan in range(index + 1, len(lines) + 1):
            candidate = lines[scan - 1]
            stripped = candidate.strip()
            if not stripped:
                continue
            current_indent = len(candidate) - len(candidate.lstrip(" "))
            if current_indent <= indent and not candidate.lstrip().startswith("#"):
                end_line = scan - 1
                break
        body = "\n".join(lines[index - 1 : end_line])
        functions.append(
            FunctionDef(
                name=match.group("name"),
                file_path=file_path,
                start_line=index,
                end_line=end_line,
                body=body,
                language="python",
            )
        )
    return functions


def find_brace_block(lines: list[str], start_index: int) -> int:
    started = False
    depth = 0
    for index in range(start_index, len(lines)):
        line = lines[index]
        for character in line:
            if character == "{":
                depth += 1
                started = True
            elif character == "}":
                depth -= 1
                if started and depth <= 0:
                    return index + 1
    return len(lines)


def parse_javascript_functions(file_path: str, content: str) -> list[FunctionDef]:
    lines = content.splitlines()
    functions: list[FunctionDef] = []

    for index, line in enumerate(lines, start=1):
        match = JS_FUNCTION_RE.match(line) or JS_ARROW_RE.match(line)
        if not match:
            continue
        end_line = find_brace_block(lines, index - 1)
        body = "\n".join(lines[index - 1 : end_line])
        functions.append(
            FunctionDef(
                name=match.group("name"),
                file_path=file_path,
                start_line=index,
                end_line=end_line,
                body=body,
                language="javascript",
            )
        )
    return functions


def parse_functions(file_path: str, content: str) -> list[FunctionDef]:
    language = detect_language(file_path)
    if language == "python":
        return parse_python_functions(file_path, content)
    if language == "javascript":
        return parse_javascript_functions(file_path, content)
    return []


def resolve_python_module(repo_root: Path, current_file: str, module_name: str) -> str | None:
    if not module_name:
        return None

    current_path = Path(current_file)
    if module_name.startswith("."):
        trimmed = module_name.lstrip(".")
        level = len(module_name) - len(trimmed)
        base_dir = current_path.parent
        for _ in range(max(level - 1, 0)):
            base_dir = base_dir.parent
        module_path = (base_dir / trimmed.replace(".", "/")) if trimmed else base_dir
    else:
        module_path = Path(module_name.replace(".", "/"))

    candidates = [
        repo_root / f"{module_path}.py",
        repo_root / module_path / "__init__.py",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate.relative_to(repo_root))
    return None


def resolve_javascript_module(repo_root: Path, current_file: str, module_name: str) -> str | None:
    if not module_name or not module_name.startswith("."):
        return None

    base_path = (Path(current_file).parent / module_name).as_posix()
    base = repo_root / base_path
    candidates = [
        base,
        base.with_suffix(".js"),
        base.with_suffix(".jsx"),
        base.with_suffix(".ts"),
        base.with_suffix(".tsx"),
        base / "index.js",
        base / "index.ts",
        base / "index.tsx",
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return str(candidate.relative_to(repo_root))
    return None


def parse_python_imports(repo_root: Path, file_path: str, content: str) -> dict[str, ImportTarget]:
    imports: dict[str, ImportTarget] = {}
    for line in content.splitlines():
        from_match = PYTHON_FROM_IMPORT_RE.match(line)
        if from_match:
            module_name = from_match.group(1)
            module_file = resolve_python_module(repo_root, file_path, module_name)
            if not module_file:
                continue
            names = [part.strip() for part in from_match.group(2).split(",")]
            for name in names:
                if not name or name == "*":
                    continue
                alias = name
                symbol = name
                if " as " in name:
                    symbol, alias = [part.strip() for part in name.split(" as ", maxsplit=1)]
                imports[alias] = ImportTarget(module_file, symbol=symbol)
            continue

        import_match = PYTHON_IMPORT_RE.match(line)
        if not import_match:
            continue
        module_name = import_match.group(1)
        module_file = resolve_python_module(repo_root, file_path, module_name)
        if not module_file:
            continue
        alias = import_match.group(2) or module_name.rsplit(".", maxsplit=1)[-1]
        imports[alias] = ImportTarget(module_file)
    return imports


def parse_js_imports(repo_root: Path, file_path: str, content: str) -> dict[str, ImportTarget]:
    imports: dict[str, ImportTarget] = {}
    for line in content.splitlines():
        import_match = JS_IMPORT_RE.match(line)
        if import_match:
            imported = import_match.group(1).strip()
            module_file = resolve_javascript_module(repo_root, file_path, import_match.group(2))
            if not module_file:
                continue
            if imported.startswith("{") and imported.endswith("}"):
                names = [part.strip() for part in imported.strip("{}").split(",")]
                for name in names:
                    if not name:
                        continue
                    alias = name
                    symbol = name
                    if " as " in name:
                        symbol, alias = [part.strip() for part in name.split(" as ", maxsplit=1)]
                    imports[alias] = ImportTarget(module_file, symbol=symbol)
                continue
            if imported.startswith("* as "):
                alias = imported.split(" ", maxsplit=2)[-1].strip()
                imports[alias] = ImportTarget(module_file)
                continue
            imports[imported] = ImportTarget(module_file)
            continue

        require_match = JS_REQUIRE_RE.match(line)
        if not require_match:
            continue
        module_file = resolve_javascript_module(repo_root, file_path, require_match.group(2))
        if module_file:
            imports[require_match.group(1)] = ImportTarget(module_file)
    return imports


def parse_imports(repo_root: Path, file_path: str, content: str) -> dict[str, ImportTarget]:
    language = detect_language(file_path)
    if language == "python":
        return parse_python_imports(repo_root, file_path, content)
    if language == "javascript":
        return parse_js_imports(repo_root, file_path, content)
    return {}


def build_repo_index(repo_root: Path) -> tuple[dict[str, list[FunctionDef]], dict[str, dict[str, ImportTarget]]]:
    function_index: dict[str, list[FunctionDef]] = {}
    import_index: dict[str, dict[str, ImportTarget]] = {}

    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        if any(part.startswith(".") and part != "." for part in path.relative_to(repo_root).parts):
            continue
        content = read_text_file(path)
        if content is None:
            continue
        relative_path = str(path.relative_to(repo_root))
        functions = parse_functions(relative_path, content)
        if functions:
            function_index[relative_path] = functions
        import_index[relative_path] = parse_imports(repo_root, relative_path, content)

    return function_index, import_index


def lookup_function(function_index: dict[str, list[FunctionDef]], file_path: str, name: str | None = None) -> FunctionDef | None:
    functions = function_index.get(file_path, [])
    if name is None:
        return functions[0] if functions else None
    for function in functions:
        if function.name == name:
            return function
    return None


def fallback_lookup(function_index: dict[str, list[FunctionDef]], name: str) -> FunctionDef | None:
    matches = [
        function
        for functions in function_index.values()
        for function in functions
        if function.name == name
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def extract_calls(function: FunctionDef) -> list[str]:
    calls: list[str] = []
    seen: set[str] = set()
    for call_name in CALL_RE.findall(function.body):
        normalized = call_name.strip()
        if not normalized:
            continue
        head = normalized.split(".", maxsplit=1)[0]
        if head in KEYWORD_CALLS:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        calls.append(normalized)
    return calls


def resolve_call(
    caller: FunctionDef,
    call_name: str,
    function_index: dict[str, list[FunctionDef]],
    import_index: dict[str, dict[str, ImportTarget]],
) -> ResolvedCall | None:
    imports = import_index.get(caller.file_path, {})
    if "." in call_name:
        qualifier, attr = call_name.split(".", maxsplit=1)
        if qualifier in {"self", "cls", "this"}:
            target = lookup_function(function_index, caller.file_path, attr)
            return ResolvedCall(target, call_name) if target else None
        target_import = imports.get(qualifier)
        if target_import is not None:
            target = lookup_function(function_index, target_import.file_path, attr)
            return ResolvedCall(target, call_name) if target else None
        return None

    imported = imports.get(call_name)
    if imported is not None:
        target = lookup_function(function_index, imported.file_path, imported.symbol or call_name)
        if target:
            return ResolvedCall(target, call_name)

    local_target = lookup_function(function_index, caller.file_path, call_name)
    if local_target is not None and local_target.key != caller.key:
        return ResolvedCall(local_target, call_name)

    fallback = fallback_lookup(function_index, call_name)
    if fallback is not None and fallback.key != caller.key:
        return ResolvedCall(fallback, call_name)
    return None


def detect_sink(function: FunctionDef) -> str | None:
    for pattern, description in SINK_MATCHERS:
        if pattern.search(function.body):
            return description
    return None


def function_contains_any_line(function: FunctionDef, lines: set[int]) -> bool:
    return any(function.start_line <= line <= function.end_line for line in lines)


def select_root_functions(
    file_path: str,
    functions: list[FunctionDef],
    file_findings: list[dict[str, Any]],
    changed_lines: set[int] | None,
) -> list[tuple[FunctionDef, int]]:
    if not functions:
        return []

    finding_lines = {
        int(finding.get("line", 0) or 0)
        for finding in file_findings
        if int(finding.get("line", 0) or 0) > 0
    }
    candidate_lines = changed_lines or finding_lines

    roots: list[tuple[FunctionDef, int]] = []
    for function in functions:
        if candidate_lines and not function_contains_any_line(function, candidate_lines):
            continue
        related_line = next(
            (
                line
                for line in sorted(finding_lines)
                if function.start_line <= line <= function.end_line
            ),
            function.start_line,
        )
        roots.append((function, related_line))

    if roots:
        return roots

    if not file_findings:
        return []

    nearest = min(
        functions,
        key=lambda function: min(abs(int(finding.get("line", 0) or 0) - function.start_line) for finding in file_findings),
    )
    line = int(file_findings[0].get("line", nearest.start_line) or nearest.start_line)
    return [(nearest, line)]


def build_static_chain(functions: list[FunctionDef], sink_description: str) -> str:
    parts: list[str] = []
    for index, function in enumerate(functions):
        label = "[changed]" if index == 0 else "[unchanged]"
        parts.append(f"{function.name}() {label}")
    parts.append(f"{sink_description} [sink]")
    return " -> ".join(parts)


def analyze_chain(
    root_function: FunctionDef,
    chain_functions: list[FunctionDef],
    sink_description: str,
    max_depth: int,
    domain_context: dict[str, Any] | None,
    provider: dict[str, str],
) -> dict[str, Any]:
    response = ai_provider.generate_text(
        build_system_prompt(),
        build_user_prompt(root_function, chain_functions, sink_description, max_depth, domain_context),
        provider,
        max_tokens=MAX_RESPONSE_TOKENS,
    )
    return normalize_chain_response(parse_json_object(response))


def traverse_from_function(
    root_function: FunctionDef,
    current_function: FunctionDef,
    function_index: dict[str, list[FunctionDef]],
    import_index: dict[str, dict[str, ImportTarget]],
    changed_files: set[str],
    max_depth: int,
    path: list[FunctionDef],
    visited: set[tuple[str, str, int]],
    left_changed_files: bool,
) -> list[tuple[list[FunctionDef], str]]:
    if len(path) - 1 >= max_depth:
        return []

    chains: list[tuple[list[FunctionDef], str]] = []
    for call_name in extract_calls(current_function):
        resolved = resolve_call(current_function, call_name, function_index, import_index)
        if resolved is None or resolved.function.key in visited:
            continue

        target = resolved.function
        target_left_changed = left_changed_files or target.file_path not in changed_files
        next_path = [*path, target]
        sink_description = detect_sink(target)
        if sink_description and target_left_changed:
            chains.append((next_path, sink_description))

        next_visited = set(visited)
        next_visited.add(target.key)
        chains.extend(
            traverse_from_function(
                root_function,
                target,
                function_index,
                import_index,
                changed_files,
                max_depth,
                next_path,
                next_visited,
                target_left_changed,
            )
        )
    return chains


def append_cross_file_findings(
    payload: dict[str, Any],
    repo_root: Path,
    domain_context: dict[str, Any] | None = None,
    base_sha: str | None = None,
    head_sha: str | None = None,
) -> dict[str, Any]:
    findings = [dict(finding) for finding in payload.get("findings", [])]
    if not findings:
        return build_output_payload(payload, findings)

    provider = select_provider()
    if provider is None:
        return build_output_payload(payload, findings)

    function_index, import_index = build_repo_index(repo_root)
    if not function_index:
        return build_output_payload(payload, findings, cross_file_chains=0)

    changed_files = {
        str(file_path)
        for file_path in payload.get("source", {}).get("changed_files", [])
        if detect_language(str(file_path))
    }
    if not changed_files:
        return build_output_payload(payload, findings, cross_file_chains=0)

    resolved_base_sha, resolved_head_sha = resolve_diff_range(payload, base_sha, head_sha)
    max_depth = max(int(os.getenv("CALL_GRAPH_MAX_DEPTH", str(DEFAULT_MAX_DEPTH)) or DEFAULT_MAX_DEPTH), 1)
    findings_by_file: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        findings_by_file.setdefault(str(finding.get("file", "")), []).append(finding)

    appended: list[dict[str, Any]] = []
    seen_chains: set[tuple[str, int, str]] = set()

    for file_path in sorted(changed_files):
        functions = function_index.get(file_path, [])
        if not functions:
            continue

        try:
            changed_lines = collect_added_lines(repo_root, file_path, resolved_base_sha, resolved_head_sha)
        except Exception as exc:
            print(f"Warning: unable to collect changed lines for {file_path}: {exc}", file=sys.stderr)
            changed_lines = None

        roots = select_root_functions(file_path, functions, findings_by_file.get(file_path, []), changed_lines)
        for root_function, line_number in roots:
            static_chains = traverse_from_function(
                root_function,
                root_function,
                function_index,
                import_index,
                changed_files,
                max_depth,
                [root_function],
                {root_function.key},
                left_changed_files=False,
            )
            for chain_functions, sink_description in static_chains:
                chain_key = (file_path, line_number, build_static_chain(chain_functions, sink_description))
                if chain_key in seen_chains:
                    continue
                seen_chains.add(chain_key)
                try:
                    analysis = analyze_chain(
                        root_function,
                        chain_functions[1:],
                        sink_description,
                        max_depth,
                        domain_context,
                        provider,
                    )
                except Exception as exc:
                    print(
                        (
                            "Warning: call-graph analysis failed "
                            f"({provider['name']} for {file_path}:{line_number}): {exc}"
                        ),
                        file=sys.stderr,
                    )
                    continue

                if not analysis.get("reaches_sink"):
                    continue

                chain_text = analysis.get("chain") or build_static_chain(chain_functions, sink_description)
                sink_text = analysis.get("sink_description") or sink_description
                appended.append(
                    {
                        "rule_id": "cross-file-chain",
                        "severity": "info",
                        "file": file_path,
                        "line": line_number,
                        "finding": "Cross-file taint chain detected.",
                        "cwe": "N/A",
                        "fix_suggestion": "Review the downstream call chain and confirm whether untrusted input can reach the sink.",
                        "origin": "cross-file",
                        "confidence": "low",
                        "chain": chain_text,
                        "hops": len(chain_functions) - 1,
                        "sink_description": sink_text,
                    }
                )

    return build_output_payload(payload, [*findings, *appended], cross_file_chains=len(appended))


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    domain_context = load_domain_context(args.context)
    output = append_cross_file_findings(
        payload,
        repo_root=Path(args.repo_root),
        domain_context=domain_context,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
    )
    Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
