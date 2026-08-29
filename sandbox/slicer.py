"""AST-based context slicer for the research layer.

The slicer builds lightweight call trees for Python (using the standard
``ast`` module) and for JavaScript/TypeScript and PHP (using a small
structural parser).  Given a file and a target line number it returns a
compact code slice: the functions that surround the line, their callers and
callees up to ``MAX_DEPTH`` levels, and only the imports actually referenced
by the retained code.  This keeps the context sent to child agents small
instead of shipping whole source files.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".php": "php",
    ".php5": "php",
    ".php7": "php",
    ".phtml": "php",
}
MAX_DEPTH = 2
_FOCUS_WINDOW = 15

FunctionRecord = dict[str, Any]
CallTree = dict[str, Any]


def detect_language(file_path: str | Path) -> str | None:
    """Return the slicer language name for a file, or None if unsupported."""
    return LANGUAGE_BY_SUFFIX.get(Path(file_path).suffix.lower())


def _qualified(parts: list[str], name: str) -> str:
    return ".".join([*parts, name])


def call_target_name(node: ast.AST) -> str:
    """Return the dotted callable name of an AST call-target expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        value: ast.AST = node
        while isinstance(value, ast.Attribute):
            parts.append(value.attr)
            value = value.value
        if isinstance(value, ast.Name):
            if value.id in {"self", "cls", "super"}:
                parts.reverse()
                return ".".join(parts)
            parts.append(value.id)
        parts.reverse()
        return ".".join(parts)
    return ""


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


class _PythonCollector(ast.NodeVisitor):
    """Collect function records, call edges, and import statements."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.functions: dict[str, FunctionRecord] = {}
        self.imports: list[dict[str, Any]] = []
        self._scope: list[str] = []
        self._in_class: list[str] = []

    def _lines(self, node: ast.AST) -> str:
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start)
        return "\n".join(self.text.splitlines()[start - 1 : end])

    def visit_Import(self, node: ast.Import) -> None:
        names = [alias.asname or alias.name.split(".")[0] for alias in node.names]
        self.imports.append(
            {"line": node.lineno, "text": self._lines(node).strip(), "names": names, "side_effect": False}
        )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        names = [alias.asname or alias.name for alias in node.names]
        self.imports.append(
            {"line": node.lineno, "text": self._lines(node).strip(), "names": names, "side_effect": False}
        )
        self.generic_visit(node)

    def _call_name(self, node: ast.Call) -> str:
        return call_target_name(node.func)

    def _record_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, kind: str) -> None:
        qualname = _qualified(self._scope, node.name)
        calls: list[str] = []

        class _CallCollector(ast.NodeVisitor):
            def __init__(self, target: "list[str]") -> None:
                self.target = target

            def visit_Call(self, call: ast.Call) -> Any:
                name = call_target_name(call.func)
                if name:
                    self.target.append(name)
                self.generic_visit(call)

        collector = _CallCollector(calls)
        for child in ast.iter_child_nodes(node):
            collector.visit(child)

        record: FunctionRecord = {
            "name": node.name,
            "qualname": qualname,
            "kind": kind,
            "start": node.lineno,
            "end": getattr(node, "end_lineno", node.lineno),
            "params": [arg.arg for arg in node.args.args],
            "signature": self._lines(node).splitlines()[0].strip()[:200],
            "calls": sorted(set(calls)),
            "decorators": [self._lines(d).strip() for d in node.decorator_list],
        }
        self.functions[qualname] = record

        self._scope.append(node.name)
        if kind == "method":
            self._in_class.append(node.name)
        self.generic_visit(node)
        if kind == "method":
            self._in_class.pop()
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        kind = "method" if self._in_class else "function"
        self._record_function(node, kind)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        kind = "method" if self._in_class else "function"
        self._record_function(node, kind)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope.append(node.name)
        self._in_class.append(node.name)
        self.generic_visit(node)
        self._in_class.pop()
        self._scope.pop()


def _extract_python(text: str) -> tuple[dict[str, FunctionRecord], list[dict[str, Any]]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}, []
    collector = _PythonCollector(text)
    collector.visit(tree)
    return collector.functions, collector.imports


# ---------------------------------------------------------------------------
# JavaScript / TypeScript and PHP structural extraction
# ---------------------------------------------------------------------------

_JS_CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch", "with", "return", "typeof", "new", "delete"}
_JS_FUNC_PATTERNS = (
    re.compile(r"\bfunction\s*([A-Za-z_$][\w$]*)\s*\("),
    re.compile(r"\b([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\s*\("),
    re.compile(r"\b([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{"),
    re.compile(r"\b([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?[A-Za-z_$][\w$]*\s*=>\s*\{"),
    re.compile(r"\b(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"),
    re.compile(r"\bfunction\s*\([^)]*\)\s*\{"),
    re.compile(r"\((?:[^)]*)\)\s*=>\s*\{"),
    re.compile(r"[A-Za-z_$][\w$]*\s*=>\s*\{"),
)
_JS_CALL_PATTERN = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
_JS_MEMBER_CALL_PATTERN = re.compile(r"(?:\.|\?\.|::)\s*([A-Za-z_$][\w$]*)\s*\(")

_PHP_FUNC_PATTERNS = (
    re.compile(r"\bfunction\s*(?:&\s*)?([A-Za-z_][\w]*)\s*\("),
    re.compile(r"\b([A-Za-z_$][\w$]*)\s*=\s*function\s*\("),
)
_PHP_CALL_PATTERN = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
_PHP_MEMBER_CALL_PATTERN = re.compile(r"(?:\$?->|::)\s*([A-Za-z_][\w]*)\s*\(")


def _strip_strings_and_comments(text: str, language: str) -> str:
    """Return source with comments and string literals replaced by blanks.

    Keeps regex escapes and identifiers intact while neutralizing braces and
    quotes inside string content so the structural parser stays simple.
    """
    if language == "php":
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
        text = re.sub(r"(?m)//.*$", " ", text)
        text = re.sub(r"(?m)#.*$", " ", text)
    else:
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
        text = re.sub(r"(?m)//.*$", " ", text)
    text = re.sub(r"`(?:\\.|[^`])*`", " ", text)
    text = re.sub(r"'(?:\\.|[^'])*'", " ", text)
    text = re.sub(r'"(?:\\.|[^"])*"', " ", text)
    return text


def _match_braces(text: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(text) - 1


def _params_of_signature(signature: str) -> list[str]:
    match = re.search(r"\(([^)]*)\)", signature)
    if not match:
        return []
    body = match.group(1)
    return [part.strip() for part in body.split(",") if part.strip()]


def _extract_structural(text: str, language: str) -> tuple[dict[str, FunctionRecord], list[dict[str, Any]]]:
    """Extract function records and imports for JS/TS and PHP files."""
    if language not in {"javascript", "typescript", "php"}:
        return {}, []
    stripped = _strip_strings_and_comments(text, language)
    clean_lines = text.splitlines()
    functions: dict[str, FunctionRecord] = {}
    imports: list[dict[str, Any]] = []

    if language in {"javascript", "typescript"}:
        import_pattern = re.compile(r"^\s*import\s+([^;]+?)\s+from\s+['\"]", re.MULTILINE)
        for match in import_pattern.finditer(stripped):
            line_no = stripped[: match.start()].count("\n") + 1
            clause = match.group(1)
            names: list[str] = []
            if "{" in clause:
                names = re.findall(r"([A-Za-z_$][\w$]*)\s*(?:as\s+([A-Za-z_$][\w$]*))?", clause)
                names = [alias[1] or alias[0] for alias in names]
            else:
                names = [clause.strip().split(" as ")[-1].strip()]
            imports.append(
                {
                    "line": line_no,
                    "text": clean_lines[line_no - 1].strip(),
                    "names": [n for n in names if n and n not in {"default", "import"}],
                    "side_effect": False,
                }
            )
        for match in re.finditer(r"^\s*import\s+['\"][^'\"]+['\"]\s*;?", stripped, re.MULTILINE):
            line_no = stripped[: match.start()].count("\n") + 1
            imports.append({"line": line_no, "text": clean_lines[line_no - 1].strip(), "names": [], "side_effect": True})
        patterns = _JS_FUNC_PATTERNS
    else:
        use_pattern = re.compile(r"^\s*use\s+([^;]+);", re.MULTILINE)
        for match in use_pattern.finditer(stripped):
            line_no = stripped[: match.start()].count("\n") + 1
            clause = match.group(1)
            imports.append(
                {
                    "line": line_no,
                    "text": clean_lines[line_no - 1].strip(),
                    "names": [clause.strip().split("\\")[-1].split(" as ")[-1].strip()],
                    "side_effect": False,
                }
            )
        include_pattern = re.compile(r"^\s*(?:include|require)(?:_once)?\s+['\"]", re.MULTILINE)
        for match in include_pattern.finditer(stripped):
            line_no = stripped[: match.start()].count("\n") + 1
            imports.append({"line": line_no, "text": clean_lines[line_no - 1].strip(), "names": [], "side_effect": True})
        patterns = _PHP_FUNC_PATTERNS

    found: list[tuple[str, str, int, int]] = []  # (name, kind, start_line, end_line)
    for pattern in patterns:
        for match in pattern.finditer(stripped):
            try:
                name = match.group(1)
            except IndexError:
                name = None
            if language in {"javascript", "typescript"} and name in _JS_CONTROL_KEYWORDS:
                continue
            start_index = match.start()
            brace_index = stripped.find("{", start_index)
            if brace_index == -1:
                continue
            end_index = _match_braces(stripped, brace_index)
            if end_index <= brace_index:
                continue
            start_line = stripped[:start_index].count("\n") + 1
            end_line = stripped[:end_index].count("\n") + 1
            if name is None:
                name = f"callback_{start_line}"
            if any(start_line <= s <= end_line and end_line <= e for s, e in [(f[2], f[3]) for f in found]):
                continue
            kind = "function"
            found.append((name, kind, start_line, end_line))

    for name, kind, start_line, end_line in found:
        if name in functions:
            existing = functions[name]
            if start_line >= existing["start"] and end_line <= existing["end"]:
                continue
        body_lines = clean_lines[start_line - 1 : end_line]
        signature = body_lines[0].strip()[:200] if body_lines else name
        calls: list[str] = []
        for number, line in enumerate(body_lines, start=start_line):
            for call_match in _JS_CALL_PATTERN.finditer(line) if language in {"javascript", "typescript"} else _PHP_CALL_PATTERN.finditer(line):
                call_name = call_match.group(1)
                if call_name == name or call_name in _JS_CONTROL_KEYWORDS:
                    continue
                calls.append(call_name)
            member_pattern = _JS_MEMBER_CALL_PATTERN if language in {"javascript", "typescript"} else _PHP_MEMBER_CALL_PATTERN
            for call_match in member_pattern.finditer(line):
                calls.append(call_match.group(1))
        record: FunctionRecord = {
            "name": name,
            "qualname": name,
            "kind": kind,
            "start": start_line,
            "end": end_line,
            "params": _params_of_signature(signature),
            "signature": signature,
            "calls": sorted(set(calls)),
            "decorators": [],
        }
        functions[name] = record

    return functions, imports


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_call_tree(file_path: str | Path) -> CallTree:
    """Build a call tree for a source file.

    Returns a dict with ``language``, ``functions`` (keyed by qualified
    name), ``imports``, ``callers`` (reverse call edges), and ``by_segment``
    (a name lookup index for calls that use only the last segment).
    """
    path = Path(file_path)
    language = detect_language(path)
    if language is None:
        return {"language": None, "functions": {}, "imports": [], "callers": {}, "by_segment": {}}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"language": language, "functions": {}, "imports": [], "callers": {}, "by_segment": {}}

    if language == "python":
        functions, imports = _extract_python(text)
    else:
        functions, imports = _extract_structural(text, language)

    callers: dict[str, list[str]] = {qualname: [] for qualname in functions}
    by_segment: dict[str, list[str]] = {}
    for qualname, record in functions.items():
        by_segment.setdefault(record["name"], []).append(qualname)
        for called in record["calls"]:
            segments = [seg for seg in called.split(".") if seg not in {"self", "cls", "super"}]
            if not segments:
                continue
            for target_name in (called, segments[-1], ".".join(segments)):
                for target_qualname in by_segment.get(target_name, []):
                    if target_qualname != qualname and qualname not in callers.setdefault(target_qualname, []):
                        callers[target_qualname].append(qualname)
                if target_name in functions:
                    if qualname not in callers.setdefault(target_name, []):
                        callers[target_name].append(qualname)
    return {
        "language": language,
        "functions": functions,
        "imports": imports,
        "callers": callers,
        "by_segment": by_segment,
    }


def _enclosing_function(tree: CallTree, line_number: int) -> FunctionRecord | None:
    candidates = [
        record
        for record in tree["functions"].values()
        if record["start"] <= line_number <= record["end"]
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda record: record["end"] - record["start"])


def _breadth_first_neighbours(tree: CallTree, start: str) -> dict[str, int]:
    """Return functions within MAX_DEPTH edges of the start function."""
    included: dict[str, int] = {start: 0}
    frontier = [start]
    depth = 0
    while frontier and depth < MAX_DEPTH:
        next_frontier: list[str] = []
        for name in frontier:
            neighbours = list(tree["callers"].get(name, []))
            neighbours.extend(tree["functions"][name]["calls"])
            for neighbour in neighbours:
                segment = neighbour.split(".")[-1]
                resolved: list[str] = []
                if neighbour in tree["functions"]:
                    resolved.append(neighbour)
                resolved.extend(tree["by_segment"].get(segment, []))
                for resolved_name in resolved:
                    if resolved_name not in included:
                        included[resolved_name] = depth + 1
                        next_frontier.append(resolved_name)
        frontier = next_frontier
        depth += 1
    return included


def _referenced_identifiers(source: str) -> set[str]:
    return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", source))


def _keep_imports(tree: CallTree, included_source: str) -> list[dict[str, Any]]:
    used = _referenced_identifiers(included_source)
    kept: list[dict[str, Any]] = []
    for import_stmt in tree["imports"]:
        if import_stmt.get("side_effect"):
            kept.append(import_stmt)
            continue
        if any(name in used for name in import_stmt["names"]):
            kept.append(import_stmt)
    return kept


def get_code_slice(file_path: str | Path, line_number: int) -> dict[str, Any]:
    """Return a focused slice of ``file_path`` around ``line_number``.

    The returned dict contains the retained function sources (target plus
    callers/callees up to ``MAX_DEPTH`` levels), the imports those functions
    actually reference, and metadata describing the call graph so consumers
    can reason about the surrounding control flow.
    """
    path = Path(file_path)
    language = detect_language(path)
    result: dict[str, Any] = {
        "file": str(path),
        "line": line_number,
        "language": language,
    }
    if language is None:
        result["error"] = "unsupported language"
        result["slice"] = ""
        result["functions_included"] = []
        return result
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        result["error"] = str(exc)
        result["slice"] = ""
        result["functions_included"] = []
        return result

    tree = build_call_tree(path)
    target = _enclosing_function(tree, line_number)
    if target is None:
        start = max(0, line_number - _FOCUS_WINDOW - 1)
        end = min(len(lines), line_number + _FOCUS_WINDOW)
        result.update(
            {
                "target_function": None,
                "callers_of_target": [],
                "callees_of_target": [],
                "functions_included": [],
                "imports_kept": [],
                "imports_stripped": len(tree["imports"]),
                "slice": "\n".join(lines[start:end]),
                "focus_window": {"start": start + 1, "end": end},
            }
        )
        return result

    included = _breadth_first_neighbours(tree, target["qualname"])
    selected = [tree["functions"][name] for name in sorted(included, key=lambda n: tree["functions"][n]["start"])]

    included_source = "\n".join(
        "\n".join(lines[record["start"] - 1 : record["end"]]) for record in selected
    )
    kept_imports = _keep_imports(tree, included_source)
    stripped_count = len(tree["imports"]) - len(kept_imports)
    slice_lines: list[str] = [imp["text"] for imp in kept_imports if imp["line"] <= target["start"]]
    for record in selected:
        body = lines[record["start"] - 1 : record["end"]]
        if body:
            slice_lines.append("\n".join(body))
    focus_start = max(0, line_number - _FOCUS_WINDOW // 2 - 1)
    focus_end = min(len(lines), line_number + _FOCUS_WINDOW // 2)

    result.update(
        {
            "target_function": target["qualname"],
            "target_signature": target["signature"],
            "callers_of_target": sorted(tree["callers"].get(target["qualname"], [])),
            "callees_of_target": sorted(set(target["calls"])),
            "functions_included": [record["qualname"] for record in selected],
            "functions_depth": {record["qualname"]: included[record["qualname"]] for record in selected},
            "imports_kept": [imp["text"] for imp in kept_imports],
            "imports_stripped": stripped_count,
            "slice": "\n".join(slice_lines),
            "focus_window": {"start": focus_start + 1, "end": focus_end},
            "focus_lines": lines[focus_start:focus_end],
        }
    )
    return result
