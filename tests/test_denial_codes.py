"""Tests verifying denial code standardization."""
import pytest
from agos.core.denial_codes import ALL_DENIAL_CODES, is_valid_denial_code
from agos.core.policy import PolicyEngine, PolicyDecision
from agos.security.capabilities import Capability

def test_all_denial_codes_are_strings():
    assert all(isinstance(code, str) for code in ALL_DENIAL_CODES)

def test_is_valid_denial_code():
    assert is_valid_denial_code('APPROVAL_REQUIRED') is True
    assert is_valid_denial_code('NONEXISTENT_CODE') is False

def test_policy_engine_deny_has_reason_code():
    engine = PolicyEngine()
    res = engine.authorize(Capability.WRITE, operation=None)
    assert res.decision == PolicyDecision.DENY
    assert hasattr(res, 'reason_code')
    assert isinstance(res.reason_code, str)
    assert len(res.reason_code) > 0
