"""
AGOS 4.1 Integration Test Suite: PyCQA Bandit CWE Benchmark Suite.

Verifies that AGOS zero-dependency AST-SAST engine detects 100% of standard
high-risk CWE vulnerability patterns (eval, exec, subprocess shell=True,
pickle deserialization, unsafe yaml loading) while producing zero false positives
on secure reference patterns.
"""
import json
from pathlib import Path
import pytest

from agos.tools.security import scan_python_ast_sast, SecurityScannerTool


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "bandit_cwe_benchmarks.json"


def load_bandit_benchmarks():
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


BENCHMARKS = load_bandit_benchmarks()
VULNERABLE_CASES = [case for case in BENCHMARKS if case["is_vulnerable"]]
SECURE_CASES = [case for case in BENCHMARKS if not case["is_vulnerable"]]


@pytest.mark.parametrize("case", VULNERABLE_CASES, ids=[c["id"] for c in VULNERABLE_CASES])
def test_bandit_cwe_vulnerable_patterns_detected(case):
    """Every vulnerable CWE snippet from Bandit test suite must trigger AST-SAST detection."""
    findings = scan_python_ast_sast(case["code"])
    assert len(findings) > 0, f"Expected AST-SAST detection for {case['id']} ({case['description']}), but got 0 findings"
    
    joined_findings = " ".join(findings)
    assert case["expected_finding"] in joined_findings, (
        f"Expected finding '{case['expected_finding']}' in findings: {joined_findings}"
    )


@pytest.mark.parametrize("case", SECURE_CASES, ids=[c["id"] for c in SECURE_CASES])
def test_bandit_cwe_secure_patterns_zero_false_positives(case):
    """Secure implementations must not trigger any false positives in AST-SAST."""
    findings = scan_python_ast_sast(case["code"])
    assert len(findings) == 0, (
        f"False positive in {case['id']} ({case['description']}): {findings}"
    )


def test_security_scanner_tool_blocks_bandit_cwe_files(tmp_path):
    """Full SecurityScannerTool execution rejects files containing Bandit CWE patterns."""
    for case in VULNERABLE_CASES:
        sample_file = tmp_path / f"{case['id'].lower().replace('-', '_')}.py"
        sample_file.write_text(case["code"], encoding="utf-8")
        
        scanner = SecurityScannerTool(workspace_root=tmp_path)
        output = scanner.execute(filepath=sample_file.name)
        assert "ZNALEZIONO PODATNOŚCI KRYTYCZNE" in output
        assert case["expected_finding"] in output
