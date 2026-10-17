"""Tests for AGOS 3.1 Verification Gate and Diff Validator."""
import pytest
from pathlib import Path
from agos.core.verification import VerificationGate
from agos.core.operation import Operation
from agos.core.scope import ExecutionScope

def test_verification_gate_passes_valid_code(tmp_path):
    ws = tmp_path
    app_file = ws / "good.py"
    app_file.write_text("def hello():\n    return 'world'\n", encoding="utf-8")

    scope = ExecutionScope(workspace_root=str(ws), allowed_paths=["good.py"])
    op = Operation(scope=scope)

    gate = VerificationGate()
    result = gate.verify(op, files_to_verify=["good.py"])
    assert result.passed is True
    assert len(result.violations) == 0

def test_verification_gate_fails_syntax_error(tmp_path):
    ws = tmp_path
    bad_file = ws / "bad.py"
    bad_file.write_text("invalid python ::: code", encoding="utf-8")

    scope = ExecutionScope(workspace_root=str(ws), allowed_paths=["bad.py"])
    op = Operation(scope=scope)

    gate = VerificationGate()
    result = gate.verify(op, files_to_verify=["bad.py"])
    assert result.passed is False
    assert any("Syntax error" in v for v in result.violations)

def test_verification_gate_fails_sensitive_file(tmp_path):
    ws = tmp_path
    env_file = ws / ".env"
    env_file.write_text("SECRET=xyz", encoding="utf-8")

    # Even if listed in allowed_paths, sensitive file check in verification fails
    scope = ExecutionScope(workspace_root=str(ws), allowed_paths=[".env"])
    op = Operation(scope=scope)

    gate = VerificationGate()
    result = gate.verify(op, files_to_verify=[".env"])
    assert result.passed is False
    assert any("INV-013" in v for v in result.violations)
