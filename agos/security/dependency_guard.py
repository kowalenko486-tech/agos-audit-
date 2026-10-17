"""
AGOS 3.1/3.2 — Slopsquatting & Dependency Supply-Chain Guard (Phase 2).

Zero-dependency guard against AI-hallucinated packages (*slopsquatting*),
typosquatting attacks, and unauthorized third-party dependencies in both
`requirements*.txt` files and Python AST `import` statements.
"""
import ast
import os
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, List, Optional, Set


class DependencyGuardMode(str, Enum):
    OFF = "off"
    WARN = "warn"
    ENFORCE = "enforce"

    @classmethod
    def from_env(cls) -> "DependencyGuardMode":
        raw = os.getenv("AGOS_SCANNER_MODE", "warn").strip().lower()
        for mode in cls:
            if mode.value == raw:
                return mode
        return cls.WARN


@dataclass(frozen=True)
class DependencyFinding:
    package: str
    category: str  # "TYPOSQUATTING" | "SLOPSQUATTING_PATTERN" | "UNAPPROVED_DEPENDENCY"
    line: int
    message: str


def _normalize_pkg(name: str) -> str:
    """PEP 503 canonical package/module normalization."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


# Python 3.10+ built-in standard library module names
STDLIB_MODULES: Set[str] = {
    _normalize_pkg(m) for m in getattr(sys, "stdlib_module_names", set())
} | {
    "typing", "pathlib", "dataclasses", "enum", "collections", "abc",
    "functools", "itertools", "re", "os", "sys", "json", "time", "datetime",
    "hashlib", "hmac", "base64", "unicodedata", "logging", "threading",
    "subprocess", "shutil", "tempfile", "unittest", "ast", "ctypes", "uuid",
}

# Approved AGOS runtime, transitive (requirements-pinned.txt), & test packages
APPROVED_PACKAGES: Set[str] = {
    "agos",
    "tests",
    "annotated-doc",
    "annotated-types",
    "anyio",
    "attrs",
    "bandit",
    "cffi",
    "click",
    "colorama",
    "cryptography",
    "dotenv",
    "fastapi",
    "h11",
    "httpcore",
    "httpcore2",
    "httpx",
    "httpx2",
    "idna",
    "iniconfig",
    "jiter",
    "jsonschema",
    "jsonschema-specifications",
    "jwt",
    "mcp",
    "mcp-types",
    "openai",
    "opentelemetry-api",
    "packaging",
    "pip-audit",
    "pluggy",
    "pycparser",
    "pydantic",
    "pydantic-core",
    "pygments",
    "pyjwt",
    "pytest",
    "pytest-asyncio",
    "python-dotenv",
    "python-multipart",
    "pywin32",
    "referencing",
    "rpds-py",
    "sniffio",
    "sse-starlette",
    "starlette",
    "truststore",
    "typing-extensions",
    "typing-inspection",
    "uvicorn",
}

# High-value ecosystem targets watched for typosquatting (Damerau-Levenshtein distance 1-2)
POPULAR_ECOSYSTEM_PACKAGES: Set[str] = APPROVED_PACKAGES | {
    "requests",
    "urllib3",
    "numpy",
    "pandas",
    "scipy",
    "sqlalchemy",
    "flask",
    "django",
    "boto3",
    "botocore",
    "anthropic",
    "langchain",
    "llama-index",
    "torch",
    "tensorflow",
    "scikit-learn",
    "matplotlib",
    "pillow",
    "pyyaml",
    "yaml",
    "rich",
    "typer",
    "celery",
    "redis",
    "psycopg2",
    "pymongo",
    "paramiko",
    "beautifulsoup4",
    "bs4",
    "lxml",
    "tqdm",
    "aiohttp",
    "websockets",
    "grpcio",
    "protobuf",
}

# Heuristic patterns common in LLM-hallucinated package names (slopsquatting)
SLOPSQUATTING_PATTERNS = (
    re.compile(r"(?:^|-)(?:chatgpt|gpt4|gpt5|llm|ai)-(?:helper|utils|sdk|client|core|tool|wrapper)(?:$|-)", re.I),
    re.compile(r"^py-(?:openai|gemini|anthropic|claude)-(?:helper|utils|unofficial|wrapper)", re.I),
    re.compile(r"(?:^|-)(?:auto|smart|easy|simple|magic)-(?:security|crypto|auth|sql|api)-(?:ai|py)(?:$|-)", re.I),
)


def read_text_auto_encoding(filepath: Path) -> str:
    """Reads text file handling UTF-8 (with or without BOM) and UTF-16 LE/BE BOMs."""
    raw = filepath.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes Damerau-Levenshtein (Optimal String Alignment) distance,
    treating adjacent character transpositions (e.g. 'fastpai' vs 'fastapi') as distance 1.
    """
    if s1 == s2:
        return 0
    len1, len2 = len(s1), len(s2)
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1

    d = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(len1 + 1):
        d[i][0] = i
    for j in range(len2 + 1):
        d[0][j] = j

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,      # deletion
                d[i][j - 1] + 1,      # insertion
                d[i - 1][j - 1] + cost,  # substitution
            )
            if (
                i > 1
                and j > 1
                and s1[i - 1] == s2[j - 2]
                and s1[i - 2] == s2[j - 1]
            ):
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)  # adjacent transposition
    return d[len1][len2]



class DependencyGuard:
    """
    Detects slopsquatting, typosquatting, and unapproved packages in requirements and Python code.
    """

    def __init__(self, extra_allowlist: Optional[Iterable[str]] = None) -> None:
        self.allowlist: Set[str] = set(APPROVED_PACKAGES) | set(STDLIB_MODULES)
        if extra_allowlist:
            self.allowlist.update(_normalize_pkg(p) for p in extra_allowlist)

    def check_package(
        self,
        raw_name: str,
        line: int = 1,
        local_modules: Optional[Set[str]] = None,
    ) -> Optional[DependencyFinding]:
        norm = _normalize_pkg(raw_name)
        if not norm:
            return None

        if norm in self.allowlist:
            return None

        if local_modules and norm in {_normalize_pkg(m) for m in local_modules}:
            return None

        # 1. Check slopsquatting naming heuristics (LLM-hallucinated compound names)
        for pat in SLOPSQUATTING_PATTERNS:
            if pat.search(norm):
                return DependencyFinding(
                    package=raw_name,
                    category="SLOPSQUATTING_PATTERN",
                    line=line,
                    message=(
                        f"Line {line}: Podejrzenie pakietu zhalucynowanego przez AI (slopsquatting): "
                        f"'{raw_name}' pasuje do wzorca wysokiego ryzyka."
                    ),
                )

        # 2. Check typosquatting against popular ecosystem & approved packages
        if len(norm) >= 4:
            best_target = None
            best_dist = 999
            for target in POPULAR_ECOSYSTEM_PACKAGES:
                if norm == target:
                    break
                if abs(len(norm) - len(target)) > 2:
                    continue
                dist = levenshtein_distance(norm, target)
                max_allowed_dist = 2 if (len(target) >= 8 and len(norm) >= 8) else 1
                if 1 <= dist <= max_allowed_dist and dist < best_dist:
                    best_dist = dist
                    best_target = target

            if best_target is not None:
                return DependencyFinding(
                    package=raw_name,
                    category="TYPOSQUATTING",
                    line=line,
                    message=(
                        f"Line {line}: Podejrzenie typosquattingu/slopsquattingu: pakiet '{raw_name}' "
                        f"jest niebezpiecznie podobny do '{best_target}' (odległość edycji={best_dist})."
                    ),
                )

        # 3. Unapproved dependency outside AGOS allowlist
        return DependencyFinding(
            package=raw_name,
            category="UNAPPROVED_DEPENDENCY",
            line=line,
            message=(
                f"Line {line}: Nieautoryzowana zależność '{raw_name}' spoza zatwierdzonej "
                f"allowlisty AGOS (ryzyko slopsquattingu / supply-chain)."
            ),
        )

    def scan_requirements_text(self, content: str) -> List[DependencyFinding]:
        """Scans a requirements.txt-formatted string for unapproved or typosquatted packages."""
        findings: List[DependencyFinding] = []
        req_name_re = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)")
        for idx, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "--", "git+", "http:", "https:")):
                continue
            m = req_name_re.match(line)
            if not m:
                continue
            pkg_name = m.group(1)
            finding = self.check_package(pkg_name, line=idx)
            if finding is not None:
                findings.append(finding)
        return findings

    def scan_python_imports(
        self,
        source: str,
        workspace_root: Optional[Path] = None,
    ) -> List[DependencyFinding]:
        """Parses Python AST and checks top-level imported modules against the allowlist."""
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        local_mods: Set[str] = set()
        if workspace_root and workspace_root.exists():
            try:
                for p in workspace_root.iterdir():
                    if p.is_dir() and not p.name.startswith("."):
                        local_mods.add(p.name)
                    elif p.suffix == ".py":
                        local_mods.add(p.stem)
            except Exception:
                pass

        findings: List[DependencyFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_pkg = alias.name.split(".")[0]
                    f = self.check_package(top_pkg, line=getattr(node, "lineno", 1), local_modules=local_mods)
                    if f is not None:
                        findings.append(f)
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    # Relative import (e.g. from . import foo) is local
                    continue
                if node.module:
                    top_pkg = node.module.split(".")[0]
                    f = self.check_package(top_pkg, line=getattr(node, "lineno", 1), local_modules=local_mods)
                    if f is not None:
                        findings.append(f)
        return findings


dependency_guard = DependencyGuard()
