"""AGOS 3.1/3.2 Hardened Security Scanner Tool (Secrets + AST-SAST + Slopsquatting Guard)."""
import ast
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Union
from agos.core.provenance import TrustedTool
from agos.security.capabilities import Capability
from agos.security.paths import resolve_and_validate_path, SecurityPathError
from agos.security.sensitive_files import is_sensitive_path
from agos.security.dependency_guard import dependency_guard
from agos.core.operation import Operation
from agos.core.policy import policy_engine, PolicyDecision

# HIGH-05 + Phase 2: Extended patterns — covers hardcoded HMAC secrets, provider tokens, JWTs, and private keys
SECURITY_SCAN_PATTERNS = {
    "Hardcoded API Key": r"(?i)api[_-]?key\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]",
    "Hardcoded Password": r"(?i)password\s*=\s*['\"][^'\"]{4,}['\"]",
    "Hardcoded Secret": r"(?i)(secret|_secret|system_secret)\s*=\s*b?['\"][^'\"]{6,}['\"]",
    "Hardcoded Token": r"(?i)token\s*=\s*['\"][a-zA-Z0-9_\-\.]{8,}['\"]",
    "Private Key Marker": r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    "HMAC/Signing Key Literal": r"(?i)(hmac|jwt|signing)[_\s]*(key|secret)\s*=\s*b?['\"][^'\"]{6,}['\"]",
    "Connection String": r"(?i)(connection[_-]?string|database[_-]?url)\s*=\s*['\"][^'\"]{8,}['\"]",
    "AWS Access Key Pattern": r"(?i)(aws[_-]?(access[_-]?key|secret[_-]?key))\s*=\s*['\"][A-Z0-9]{16,}['\"]",
    "AWS Access Key ID Literal": r"\bAKIA[0-9A-Z]{16}\b",
    "OpenAI API Key Literal": r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{20,}\b",
    "Google Cloud/AI Key Literal": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "GitHub Token Literal": r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b",
    "Slack Token Literal": r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",
    "Hardcoded JWT Token": r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
}


def scan_python_ast_sast(source: str) -> List[str]:
    """
    Zero-dependency AST SAST scanner detecting high-confidence vulnerabilities
    typical of AI-generated Python code (OWASP Top 10 + Sandbox Escape Heuristics).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    findings: List[str] = []
    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 1)

        # ── 1. Dynamic Reflection & Sandbox Escape Identifiers (Name) ────────
        if isinstance(node, ast.Name):
            if node.id in ("__builtins__", "__import__"):
                findings.append(
                    f"Linia {lineno}: Wykryto odwołanie do '{node.id}' (AST-SAST: Dynamic Reflection / Sandbox Escape)"
                )

        # ── 2. Meta-class / MRO / Sandbox Escape Attributes (Attribute) ──────
        elif isinstance(node, ast.Attribute):
            if node.attr in ("__subclasses__", "__bases__", "__mro__", "__globals__", "__code__", "__builtins__"):
                findings.append(
                    f"Linia {lineno}: Wykryto próbę inspekcji metaklas/refleksji '{node.attr}' (AST-SAST: MRO / Sandbox Escape)"
                )

        # ── 3. Dangerous Function and Method Calls (Call) ────────────────────
        elif isinstance(node, ast.Call):
            # Direct eval() or exec()
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                findings.append(
                    f"Linia {lineno}: Wykryto niebezpieczne wywołanie '{node.func.id}()' (AST-SAST: Code Injection)"
                )

            # getattr() called with suspicious dynamic targets or builtins
            elif isinstance(node.func, ast.Name) and node.func.id == "getattr":
                if len(node.args) >= 1:
                    first_arg = node.args[0]
                    if (isinstance(first_arg, ast.Name) and first_arg.id in ("__builtins__", "globals")) or (
                        isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Name) and first_arg.func.id == "globals"
                    ):
                        findings.append(
                            f"Linia {lineno}: Wykryto niebezpieczne wywołanie 'getattr({ast.dump(first_arg)})' (AST-SAST: Dynamic Reflection Injection)"
                        )

            elif isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                owner = node.func.value.id if isinstance(node.func.value, ast.Name) else ""

                # subprocess.*(..., shell=True)
                if owner == "subprocess" and attr in ("run", "Popen", "call", "check_call", "check_output"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append(
                                f"Linia {lineno}: Wykryto 'subprocess.{attr}(..., shell=True)' (AST-SAST: Command Injection)"
                            )

                # Insecure deserialization: pickle.load / pickle.loads / marshal.loads
                elif owner in ("pickle", "cPickle", "marshal") and attr in ("load", "loads"):
                    findings.append(
                        f"Linia {lineno}: Wykryto niebezpieczną deserializację '{owner}.{attr}()' (AST-SAST: Insecure Deserialization)"
                    )

                # Unsafe yaml.load() without SafeLoader
                elif owner == "yaml" and attr == "load":
                    has_safe_loader = False
                    for kw in node.keywords:
                        if kw.arg == "Loader" and "Safe" in ast.dump(kw.value):
                            has_safe_loader = True
                    if len(node.args) >= 2 and "Safe" in ast.dump(node.args[1]):
                        has_safe_loader = True
                    if not has_safe_loader:
                        findings.append(
                            f"Linia {lineno}: Wykryto 'yaml.load()' bez SafeLoader (AST-SAST: Arbitrary Code Execution)"
                        )

                # Dynamic module loading via importlib
                elif owner == "importlib" and attr in ("import_module", "__import__"):
                    findings.append(
                        f"Linia {lineno}: Wykryto dynamiczne ładowanie modułu '{owner}.{attr}()' (AST-SAST: Dynamic Code Injection)"
                    )

    return findings


def run_optional_bandit(filepath: Path) -> List[str]:
    """
    Optional gentle-profile Bandit SAST integration.
    Runs ONLY when AGOS_BANDIT_ENABLED=1 and 'bandit' executable is available.
    Uses gentle profile (-ll -ii -s B101,B311) to avoid false blocks on asserts/random.
    """
    if os.getenv("AGOS_BANDIT_ENABLED", "0").strip() != "1":
        return []
    bandit_bin = shutil.which("bandit")
    if not bandit_bin:
        return []
    try:
        res = subprocess.run(
            [bandit_bin, "-q", "-ll", "-ii", "-s", "B101,B311", "-f", "custom",
             "--msg-template", "Linia {line}: [Bandit {test_id}] {msg}", str(filepath)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        out_lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
        return out_lines
    except Exception:
        return []


class SecurityScannerTool(TrustedTool):
    """
    Hardened Security Scanner Tool.
    Capability: ANALYZE
    Enforces:
    - Path boundary check
    - Sensitive target check
    - Credential heuristic scan with extended patterns
    - Built-in AST-SAST & Dependency/Slopsquatting checks
    """

    def __init__(self, workspace_root: Optional[Union[str, Path]] = None):
        super().__init__(name="security_scanner")
        self.capability = Capability.ANALYZE
        self._custom_workspace = Path(workspace_root).resolve() if workspace_root else None
        self.description = "Skanuje plik w poszukiwaniu wycieków haseł, kluczy API, luk AST-SAST i slopsquattingu."
        self.parameters = {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Ścieżka do skanowanego pliku"}
            },
            "required": ["filepath"],
        }

    @property
    def workspace_root(self) -> Path:
        if self._custom_workspace:
            return self._custom_workspace
        from agos.core.workspace_manager import workspace_manager
        return workspace_manager.get_current_workspace()

    @workspace_root.setter
    def workspace_root(self, val: Union[str, Path]):
        self._custom_workspace = Path(val).resolve()

    def execute(self, filepath: str, operation: Optional[Operation] = None, **kwargs) -> str:
        ws = Path(operation.scope.workspace_root).resolve() if operation else self.workspace_root
        try:
            resolved_path = resolve_and_validate_path(filepath, ws, must_exist=True)
        except SecurityPathError as spe:
            return f"[BŁĄD BEZPIECZEŃSTWA] {spe}"

        # Policy check
        decision = policy_engine.authorize(
            capability=self.capability,
            operation=operation,
            target_path=resolved_path,
            actor="agent",
        )
        if decision.decision != PolicyDecision.ALLOW:
            return f"[ODMOWA POLITYKI] {decision.reason}"

        vulnerabilities: List[str] = []
        try:
            from agos.security.dependency_guard import read_text_auto_encoding
            content = read_text_auto_encoding(resolved_path)
            lines = content.splitlines()
            for i, line in enumerate(lines, start=1):
                for vuln_name, pattern in SECURITY_SCAN_PATTERNS.items():
                    if re.search(pattern, line):
                        vulnerabilities.append(
                            f"Linia {i}: Wykryto potencjalne zagrożenie ({vuln_name})"
                        )

            suffix = resolved_path.suffix.lower()
            name_lower = resolved_path.name.lower()

            if suffix == ".py":
                vulnerabilities.extend(scan_python_ast_sast(content))
                vulnerabilities.extend(run_optional_bandit(resolved_path))
            elif name_lower.startswith("requirements") and suffix == ".txt":
                for dep_f in dependency_guard.scan_requirements_text(content):
                    vulnerabilities.append(dep_f.message)

            if vulnerabilities:
                return "ZNALEZIONO PODATNOŚCI KRYTYCZNE:\n" + "\n".join(vulnerabilities)
            return "Brak oczywistych podatności (skan heurystyczny czysty)."
        except Exception as e:
            return f"Błąd skanera: {str(e)}"

