"""
AGOS 4.1 Integration Test Suite: Gitleaks & DLP Synthetic Secrets Benchmark.

Verifies that AGOS DLPEngine and TokenVault detect, mask, and safely handle
external synthetic API keys, cloud tokens, private keys, and PII datasets
matching standard Gitleaks / TruffleHog patterns.
"""
import base64
import json
from pathlib import Path
import pytest

from agos.security.dlp import DLPEngine, DLPMode, DLPViolationError, TokenVault


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "gitleaks_synthetic_secrets.json"


def load_secrets_benchmarks():
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


SECRETS_DATASET = load_secrets_benchmarks()
SENSITIVE_CASES = [case for case in SECRETS_DATASET if case["is_sensitive"]]
BENIGN_CASES = [case for case in SECRETS_DATASET if not case["is_sensitive"]]


@pytest.mark.parametrize("case", SENSITIVE_CASES, ids=[c["id"] for c in SENSITIVE_CASES])
def test_gitleaks_synthetic_secrets_detected_and_masked(case):
    """Synthetic secrets must be detected, replaced with tokens, and never exposed on egress."""
    engine = DLPEngine()
    vault = TokenVault()
    
    test_prompt = f"Proszę przeanalizować następujący parametr: {case['raw_value']} w konfiguracji."
    result = engine.scan_and_process(test_prompt, vault=vault, mode_override=DLPMode.ENFORCE)
    
    assert result.has_findings is True, (
        f"Expected secret finding for {case['id']} ({case['description']}), but none detected"
    )
    # The raw secret value MUST NOT appear in the sanitized egress payload
    assert case["raw_value"] not in result.sanitized_text, (
        f"Raw secret {case['id']} leaked into sanitized output: {result.sanitized_text}"
    )
    # Reversible pseudonymization: local deanonymization must perfectly restore original text
    restored = vault.deanonymize(result.sanitized_text)
    assert restored == test_prompt, f"Roundtrip deanonymization mismatch for {case['id']}"


@pytest.mark.parametrize("case", SENSITIVE_CASES, ids=[c["id"] for c in SENSITIVE_CASES])
def test_gitleaks_synthetic_secrets_blocked_in_block_mode(case):
    """In fail-closed BLOCK mode, detecting any synthetic secret must raise DLPViolationError."""
    engine = DLPEngine()
    test_prompt = f"Eksfiltracja: {case['raw_value']}"
    
    with pytest.raises(DLPViolationError):
        engine.scan_and_process(test_prompt, mode_override=DLPMode.BLOCK)


@pytest.mark.parametrize("case", BENIGN_CASES, ids=[c["id"] for c in BENIGN_CASES])
def test_benign_hashes_and_uuids_zero_false_positives(case):
    """Non-sensitive hashes and UUIDs must not trigger false positive DLP alerts."""
    engine = DLPEngine()
    vault = TokenVault()
    
    test_prompt = f"Identyfikator obiektu: {case['raw_value']}"
    result = engine.scan_and_process(test_prompt, vault=vault, mode_override=DLPMode.ENFORCE)
    
    assert result.has_findings is False, (
        f"False positive on benign value {case['id']}: findings={result.findings}"
    )
    assert result.sanitized_text == test_prompt


def test_base64_encoded_secret_exfiltration_blocked():
    """Secrets encoded in Base64 must be decoded and detected by DLPEngine."""
    raw_secret = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"
    b64_secret = base64.b64encode(raw_secret.encode("utf-8")).decode("utf-8")
    
    engine = DLPEngine()
    prompt = f"Zakodowany payload: {b64_secret}"
    
    result = engine.scan_and_process(prompt, mode_override=DLPMode.ENFORCE)
    assert result.has_findings is True
    assert any(f.category.startswith("B64_") for f in result.findings)
    assert "B64_API_KEY" in [f.category for f in result.findings]
