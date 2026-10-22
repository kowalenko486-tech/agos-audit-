"""Tests for Phase 2: Extended Secret Scanner, AST-SAST, and Slopsquatting/Dependency Guard."""
from pathlib import Path
import pytest

from agos.security.dependency_guard import (
    DependencyGuard,
    dependency_guard,
    read_text_auto_encoding,
)
from agos.tools.security import SecurityScannerTool, scan_python_ast_sast
from agos.core.verification import VerificationGate, StageStatus
from agos.core.operation import Operation
from agos.core.scope import ExecutionScope


# ── 1. Extended Secret Scanner Patterns ──────────────────────────────────────

@pytest.mark.parametrize(
    "secret_snippet,expected_label",
    [
        ('KEY = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456"', "OpenAI API Key Literal"),
        ('GCP = "AIzaSyDaGmWKa4JsXZ-HjGw7xH_example12345"', "Google Cloud/AI Key Literal"),
        ('GH = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"', "GitHub Token Literal"),
        ('SLACK = "xoxb-123456789012-123456789012-abcdef"', "Slack Token Literal"),
        (
            'JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"',
            "Hardcoded JWT Token",
        ),
        ('AWS_ID = "AKIAIOSFODNN7EXAMPLE"', "AWS Access Key ID Literal"),
    ],
)
def test_extended_secret_patterns_detected_by_scanner(tmp_path, secret_snippet, expected_label):
    f = tmp_path / "sample_module.py"
    f.write_text(f"{secret_snippet}\n", encoding="utf-8")

    scanner = SecurityScannerTool(workspace_root=tmp_path)
    output = scanner.execute(filepath="sample_module.py")
    assert "ZNALEZIONO PODATNOŚCI KRYTYCZNE" in output
    assert expected_label in output


# ── 2. Built-in Zero-Dependency AST-SAST ─────────────────────────────────────

def test_ast_sast_detects_eval_exec_subprocess_pickle_and_yaml():
    vulnerable_code = (
        "import subprocess, pickle, yaml\n"
        "def run_untrusted(user_cmd, blob, yml):\n"
        "    eval(user_cmd)\n"
        "    subprocess.run(user_cmd, shell=True)\n"
        "    pickle.loads(blob)\n"
        "    yaml.load(yml)\n"
    )
    findings = scan_python_ast_sast(vulnerable_code)
    assert len(findings) == 4
    joined = "\n".join(findings)
    assert "eval()" in joined
    assert "subprocess.run(..., shell=True)" in joined
    assert "pickle.loads()" in joined
    assert "yaml.load()" in joined


def test_ast_sast_allows_safe_alternatives():
    safe_code = (
        "import subprocess, json, yaml\n"
        "def run_safe(args_list, text, yml):\n"
        "    subprocess.run(args_list, shell=False)\n"
        "    json.loads(text)\n"
        "    yaml.load(yml, Loader=yaml.SafeLoader)\n"
    )
    assert scan_python_ast_sast(safe_code) == []


def test_ast_sast_detects_reflection_and_sandbox_escapes():
    """Verifies that dynamic reflection and sandbox escape tricks are strictly blocked."""
    # 1. getattr on __builtins__ with string concatenation bypass
    obf_getattr = 'getattr(__builtins__, "ev" + "al")("__import__(\'os\').system(\'whoami\')")\n'
    findings1 = scan_python_ast_sast(obf_getattr)
    assert len(findings1) >= 1
    assert any("__builtins__" in f or "Dynamic Reflection" in f for f in findings1)

    # 2. MRO / __subclasses__ traversal sandbox escape
    mro_escape = '().__class__.__base__.__subclasses__()[140]().load_module("os").system("whoami")\n'
    findings2 = scan_python_ast_sast(mro_escape)
    assert len(findings2) >= 1
    assert any("__subclasses__" in f for f in findings2)

    # 3. Direct __import__ call
    import_escape = '__import__("os").system("id")\n'
    findings3 = scan_python_ast_sast(import_escape)
    assert len(findings3) >= 1
    assert any("__import__" in f for f in findings3)

    # 4. importlib dynamic module execution
    importlib_escape = 'import importlib\nimportlib.import_module("os").system("whoami")\n'
    findings4 = scan_python_ast_sast(importlib_escape)
    assert len(findings4) >= 1
    assert any("importlib" in f for f in findings4)


# ── 3. DependencyGuard: Slopsquatting & Typosquatting Detection ──────────────

def test_dependency_guard_allows_approved_and_stdlib():
    guard = DependencyGuard()
    reqs = "pydantic>=2.0.0\nfastapi>=0.110.0\nopenai>=1.0.0\n"
    assert guard.scan_requirements_text(reqs) == []

    code = "import os\nimport pathlib\nimport pydantic\nfrom agos.core import policy\n"
    assert guard.scan_python_imports(code) == []


def test_dependency_guard_detects_typosquatting():
    guard = DependencyGuard()
    reqs = "reqeusts>=2.31.0\nfastpai==0.110.0\ncrytpography>=42.0.0\n"
    findings = guard.scan_requirements_text(reqs)
    assert len(findings) == 3
    assert all(f.category == "TYPOSQUATTING" for f in findings)
    assert "requests" in findings[0].message
    assert "fastapi" in findings[1].message
    assert "cryptography" in findings[2].message


def test_dependency_guard_detects_ai_slopsquatting_patterns():
    guard = DependencyGuard()
    reqs = "chatgpt-helper>=1.0.0\npy-openai-utils==0.2.1\nauto-security-ai>=0.1.0\n"
    findings = guard.scan_requirements_text(reqs)
    assert len(findings) == 3
    assert all(f.category == "SLOPSQUATTING_PATTERN" for f in findings)


def test_actual_repo_requirements_files_pass_dependency_guard():
    repo_root = Path(__file__).resolve().parent.parent
    for req_file in ("requirements.txt", "requirements-test.txt", "requirements-pinned.txt"):
        p = repo_root / req_file
        if p.exists():
            findings = dependency_guard.scan_requirements_text(read_text_auto_encoding(p))
            assert findings == [], f"Unexpected dependency findings in {req_file}: {findings}"



# ── 4. VerificationGate Integration (WARN fluidity vs ENFORCE block) ─────────

def test_verification_gate_warn_mode_preserves_fluidity_and_records_warnings(tmp_path, monkeypatch):
    monkeypatch.setenv("AGOS_SCANNER_MODE", "warn")
    target = tmp_path / "script.py"
    target.write_text(
        "import reqeusts\ndef bad(x):\n    return eval(x)\n",
        encoding="utf-8",
    )

    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=["script.py"])
    op = Operation(scope=scope)
    gate = VerificationGate()
    res = gate.verify(op, files_to_verify=["script.py"])

    # In default WARN mode, commit is NOT blocked, preserving AGOS fluidity
    assert res.passed is True
    assert res.stage_security_scan == StageStatus.PASSED
    assert len(res.security_warnings) == 2
    assert any("eval()" in w for w in res.security_warnings)
    assert any("reqeusts" in w for w in res.security_warnings)


def test_verification_gate_enforce_mode_blocks_ast_sast_and_slopsquatting(tmp_path, monkeypatch):
    monkeypatch.setenv("AGOS_SCANNER_MODE", "enforce")
    target = tmp_path / "requirements.txt"
    target.write_text("pydantic>=2.0.0\nchatgpt-helper>=1.0.0\n", encoding="utf-8")

    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=["requirements.txt"])
    op = Operation(scope=scope)
    gate = VerificationGate()
    res = gate.verify(op, files_to_verify=["requirements.txt"])

    assert res.passed is False
    assert res.stage_security_scan == StageStatus.FAILED
    assert any("INV-018" in v for v in res.violations)
    assert any("chatgpt-helper" in f for f in res.security_findings)
