"""Tests for MutationIntent and payload authorization (INV-026, INV-027, INV-040)."""
import pytest
from agos.core.mutation_intent import (
    MutationIntent, DiffPolicy, MutationType, authorize_payload, PayloadAuthorizationResult
)


def test_payload_within_authorized_target_passes():
    intent = MutationIntent(
        operation_id='OP-1',
        target_files=['app.py'],
        allowed_mutation_type=MutationType.ANY,
        diff_policy=DiffPolicy(require_high_risk_review=False),
    ).seal()
    result = authorize_payload(intent, 'app.py', 'def hello():\n    return 42\n')
    assert result.authorized is True


def test_payload_wrong_target_denied():
    """INV-026: Payload targeting unauthorized file must be denied."""
    intent = MutationIntent(
        operation_id='OP-1',
        target_files=['app.py'],
        diff_policy=DiffPolicy(require_high_risk_review=False),
    ).seal()
    result = authorize_payload(intent, 'other_file.py', 'malicious content')
    assert result.authorized is False
    assert 'PAYLOAD_NOT_AUTHORIZED' in result.reason_code


def test_payload_with_secret_pattern_denied():
    """INV-026: Payload containing secret pattern must be denied when require_high_risk_review=True."""
    intent = MutationIntent(
        operation_id='OP-1',
        target_files=['app.py'],
        diff_policy=DiffPolicy(require_high_risk_review=True),
    ).seal()
    result = authorize_payload(intent, 'app.py', 'SECRET_KEY = "s3cr3t!"')
    assert result.authorized is False
    assert 'HIGH_RISK' in result.reason_code


def test_payload_with_forbidden_pattern_denied():
    """INV-026: Payload matching forbidden_patterns must be denied."""
    intent = MutationIntent(
        operation_id='OP-1',
        target_files=['app.py'],
        diff_policy=DiffPolicy(
            require_high_risk_review=False,
            forbidden_patterns=[r'delete.*account'],
        ),
    ).seal()
    result = authorize_payload(intent, 'app.py', 'delete_account(user_id)')
    assert result.authorized is False
    assert 'FORBIDDEN_PATTERN' in result.reason_code


def test_diff_too_large_denied():
    """INV-027: Diff exceeding max_lines_added must be denied."""
    intent = MutationIntent(
        operation_id='OP-1',
        target_files=['app.py'],
        diff_policy=DiffPolicy(max_lines_added=3, require_high_risk_review=False),
    ).seal()
    large_content = '\n'.join([f'line_{i} = {i}' for i in range(10)])
    result = authorize_payload(intent, 'app.py', large_content, original_content='')
    assert result.authorized is False
    assert 'DIFF_TOO_LARGE' in result.reason_code


def test_protected_symbol_removal_denied():
    """INV-026: Removing a protected symbol from payload must be denied."""
    intent = MutationIntent(
        operation_id='OP-1',
        target_files=['app.py'],
        diff_policy=DiffPolicy(
            require_high_risk_review=False,
            protected_symbols=['authenticate'],
        ),
    ).seal()
    original = 'def authenticate(user):\n    pass\n'
    proposed = 'def login(user):\n    pass\n'  # authenticate removed
    result = authorize_payload(intent, 'app.py', proposed, original_content=original)
    assert result.authorized is False
    assert 'PROTECTED_SYMBOL_REMOVED' in result.reason_code


def test_mutation_intent_hash_is_stable():
    """MutationIntent hash must be deterministic."""
    intent1 = MutationIntent(operation_id='OP-1', target_files=['a.py', 'b.py']).seal()
    intent2 = MutationIntent(operation_id='OP-1', target_files=['b.py', 'a.py']).seal()
    assert intent1.intent_hash == intent2.intent_hash
