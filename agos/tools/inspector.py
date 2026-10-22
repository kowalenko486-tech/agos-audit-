"""AGOS 4.1 Workspace Inspector — read-only file tree, file content, structured findings,
static import graph and audit report data.

Security properties:
- Every path is resolved with resolve_and_validate_path() against the active workspace.
- Sensitive files (.env, keys, credentials, .git internals) are listed but never read.
- No code from the inspected project is imported or executed (AST parsing only).
- Hard limits on entries, file size and scanned files (bounded work, no DoS).
"""
from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from agos.security.paths import resolve_and_validate_path, SecurityPathError
from agos.security.sensitive_files import is_sensitive_path
from agos.security.dependency_guard import dependency_guard, read_text_auto_encoding
from agos.security.architecture_guard import architecture_guard
from agos.tools.security import SECURITY_SCAN_PATTERNS, scan_python_ast_sast

SKIP_DIRS = {
    ".git", "venv", ".venv", "env", "node_modules", "__pycache__", ".pytest_cache",
    ".agos_snapshots", "dist", "build", ".mypy_cache", ".ruff_cache", ".idea", ".vscode",
}
MAX_TREE_ENTRIES = 3000
MAX_TREE_DEPTH = 10
MAX_READ_BYTES = 1_000_000
MAX_SCAN_FILES = 400

_AST_LINE_RE = re.compile(r"^Linia (\d+): (.*)$")


class InspectorError(Exception):
    """Raised for client-visible, safe-to-report inspector errors."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _rel(path: Path, ws: Path) -> str:
    return path.relative_to(ws).as_posix()


def list_tree(ws: Path) -> Dict[str, Any]:
    """Lists workspace files (bounded). Sensitive files are flagged, never read."""
    ws = ws.resolve()
    entries: List[Dict[str, Any]] = []
    truncated = False

    def walk(directory: Path, depth: int) -> None:
        nonlocal truncated
        if depth > MAX_TREE_DEPTH or truncated:
            return
        try:
            children = sorted(directory.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except OSError:
            return
        for child in children:
            if len(entries) >= MAX_TREE_ENTRIES:
                truncated = True
                return
            if child.is_symlink():
                continue  # never follow links out of the workspace
            if child.is_dir():
                if child.name in SKIP_DIRS:
                    continue
                entries.append({"path": _rel(child, ws), "type": "dir"})
                walk(child, depth + 1)
            elif child.is_file():
                try:
                    size = child.stat().st_size
                except OSError:
                    size = 0
                entries.append({
                    "path": _rel(child, ws),
                    "type": "file",
                    "size": size,
                    "sensitive": bool(is_sensitive_path(child)),
                })

    walk(ws, 0)
    return {"workspace": str(ws), "entries": entries, "truncated": truncated}


def resolve_readable(ws: Path, rel_path: str) -> Path:
    """Resolves a workspace-relative path for reading; denies escapes and sensitive files."""
    if not rel_path or "\x00" in rel_path:
        raise InspectorError("Nieprawidłowa ścieżka.")
    try:
        resolved = resolve_and_validate_path(rel_path, ws.resolve(), must_exist=True)
    except SecurityPathError as spe:
        raise InspectorError(f"Odmowa: {spe}", status=403)
    if is_sensitive_path(resolved):
        raise InspectorError("Odmowa: plik wrażliwy (INV-013) — odczyt zablokowany.", status=403)
    if not resolved.is_file():
        raise InspectorError("To nie jest plik.")
    if resolved.stat().st_size > MAX_READ_BYTES:
        raise InspectorError(f"Plik przekracza limit {MAX_READ_BYTES} bajtów.", status=413)
    return resolved


def read_text_file(ws: Path, rel_path: str) -> Dict[str, Any]:
    resolved = resolve_readable(ws, rel_path)
    raw = resolved.read_bytes()
    if b"\x00" in raw[:8192]:
        raise InspectorError("Plik binarny — podgląd niedostępny.", status=415)
    content = read_text_auto_encoding(resolved)
    return {
        "path": _rel(resolved, ws.resolve()),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "content": content,
    }


def scan_content(content: str, filename: str) -> List[Dict[str, Any]]:
    """Structured findings: [{line, rule, severity, message}] (no code execution)."""
    findings: List[Dict[str, Any]] = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        for name, pattern in SECURITY_SCAN_PATTERNS.items():
            if re.search(pattern, line):
                findings.append({"line": i, "rule": "SECRET", "severity": "HIGH",
                                 "message": f"Możliwy sekret w kodzie: {name}"})

    name_lower = Path(filename).name.lower()
    suffix = Path(filename).suffix.lower()

    if suffix == ".py":
        try:
            ast.parse(content)
        except SyntaxError as se:
            findings.append({"line": se.lineno or 1, "rule": "SYNTAX", "severity": "HIGH",
                             "message": f"Błąd składni: {se.msg}"})
        for msg in scan_python_ast_sast(content):
            m = _AST_LINE_RE.match(msg)
            findings.append({
                "line": int(m.group(1)) if m else 1,
                "rule": "AST-SAST",
                "severity": "CRITICAL",
                "message": m.group(2) if m else msg,
            })
    elif name_lower.startswith("requirements") and suffix == ".txt":
        for f in dependency_guard.scan_requirements_text(content):
            findings.append({"line": f.line, "rule": "SUPPLY-CHAIN", "severity": "MEDIUM",
                             "message": f.message})
        for i, line in enumerate(lines, start=1):
            stripped = line.split("#", 1)[0].strip()
            if stripped and not stripped.startswith("-") and "==" not in stripped:
                findings.append({"line": i, "rule": "UNPINNED", "severity": "MEDIUM",
                                 "message": f"Zależność bez sztywnej wersji (==): '{stripped}'"})

    for v in architecture_guard.check_file_hygiene(Path(filename), content=content):
        findings.append({"line": 1, "rule": "INV-042", "severity": "LOW", "message": v.message})

    findings.sort(key=lambda f: (f["line"], f["rule"]))
    return findings


def scan_file(ws: Path, rel_path: str) -> Dict[str, Any]:
    data = read_text_file(ws, rel_path)
    return {"path": data["path"], "sha256": data["sha256"],
            "findings": scan_content(data["content"], data["path"])}


def _iter_files(ws: Path, suffixes: Optional[tuple] = None) -> List[Path]:
    out: List[Path] = []
    for entry in list_tree(ws)["entries"]:
        if entry["type"] != "file" or entry.get("sensitive"):
            continue
        if suffixes and not entry["path"].lower().endswith(suffixes):
            continue
        out.append(ws.resolve() / entry["path"])
        if len(out) >= MAX_SCAN_FILES:
            break
    return out


def import_graph(ws: Path) -> Dict[str, Any]:
    """Static import graph of local Python modules (AST only, nothing is executed)."""
    ws = ws.resolve()
    files = _iter_files(ws, (".py",))
    modules: Dict[str, Path] = {}
    for f in files:
        rel = f.relative_to(ws).with_suffix("")
        parts = list(rel.parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        if parts:
            modules[".".join(parts)] = f

    def resolve_local(name: str) -> Optional[str]:
        while name:
            if name in modules:
                return name
            if "." not in name:
                return None
            name = name.rsplit(".", 1)[0]
        return None

    nodes: List[Dict[str, Any]] = []
    errors: List[str] = []
    for mod, path in sorted(modules.items()):
        local, external = set(), set()
        try:
            tree = ast.parse(read_text_auto_encoding(path))
        except Exception as e:
            errors.append(f"{mod}: {e}")
            nodes.append({"module": mod, "path": _rel(path, ws), "imports": [], "external": [],
                          "parse_error": True})
            continue
        pkg = mod.rsplit(".", 1)[0] if "." in mod else ""
        for node in ast.walk(tree):
            names: List[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    anchor = pkg.split(".") if pkg else []
                    anchor = anchor[: max(0, len(anchor) - (node.level - 1))]
                    base = ".".join([p for p in anchor + ([base] if base else []) if p])
                names = [base] + [f"{base}.{a.name}" if base else a.name for a in node.names]
            for n in names:
                hit = resolve_local(n)
                if hit and hit != mod:
                    local.add(hit)
                elif n and not hit and not node_is_relative(node):
                    external.add(n.split(".")[0])
        nodes.append({"module": mod, "path": _rel(path, ws), "imports": sorted(local),
                      "external": sorted(external - set(modules))})

    imported_by: Dict[str, List[str]] = {n["module"]: [] for n in nodes}
    for n in nodes:
        for dep in n["imports"]:
            imported_by.setdefault(dep, []).append(n["module"])
    for n in nodes:
        n["imported_by"] = sorted(imported_by.get(n["module"], []))
    return {"nodes": nodes, "errors": errors, "files_scanned": len(files)}


def node_is_relative(node: ast.AST) -> bool:
    return isinstance(node, ast.ImportFrom) and bool(node.level)


def build_report(ws: Path) -> Dict[str, Any]:
    """Aggregates real scan results for the whole workspace (bounded)."""
    ws = ws.resolve()
    tree = list_tree(ws)
    scanned: List[Dict[str, Any]] = []
    skipped_large: List[str] = []
    for f in _iter_files(ws, (".py", ".txt")):
        rel = _rel(f, ws)
        if f.suffix.lower() == ".txt" and not f.name.lower().startswith("requirements"):
            continue
        try:
            res = scan_file(ws, rel)
            scanned.append({"path": rel, "findings": res["findings"]})
        except InspectorError:
            skipped_large.append(rel)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s in scanned:
        for f in s["findings"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "workspace": str(ws),
        "files_total": sum(1 for e in tree["entries"] if e["type"] == "file"),
        "sensitive_files": [e["path"] for e in tree["entries"] if e.get("sensitive")],
        "tree_truncated": tree["truncated"],
        "scanned": scanned,
        "skipped": skipped_large,
        "counts": counts,
        "not_checked": [
            "Wykonanie testów badanego projektu (świadomie wyłączone: brak sandboxa).",
            "Podatności znane (CVE) w zależnościach — użyj pip-audit.",
            "Pliki inne niż .py i requirements*.txt (np. JS, HTML, konfiguracje).",
            "Logika biznesowa i poprawność działania aplikacji.",
            "Analiza przepływu danych (taint analysis) — skanery są heurystyczne.",
        ],
    }
