"""Tests for AGOS 3.1 Approval Gate, Expiration, and Replay Protection."""
import time
import pytest
from agos.core.scope import ExecutionScope
from agos.core.approval import ApprovalGate, ApprovalStatus

def test_approval_grant_and_verify_and_consume(tmp_path):
    gate = ApprovalGate(default_ttl_seconds=60.0)
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=["app.py"])

    approval = gate.create_request(
        operation_id="OP-2026-000001",
        actor="user",
        target="app.py",
        scope=scope,
        requested_actions=["WRITE"]
    )
    assert approval.status == ApprovalStatus.PENDING

    # Grant
    gate.grant(approval.approval_id, actor="lead_architect")
    assert approval.status == ApprovalStatus.GRANTED

    # Verify and Consume
    valid, reason = gate.verify_and_consume(
        approval_id=approval.approval_id,
        operation_id="OP-2026-000001",
        current_scope_hash=scope.compute_hash()
    )
    assert valid is True
    assert approval.status == ApprovalStatus.CONSUMED

    # Replay Protection: Second attempt must fail (INV-011)
    replay_valid, replay_reason = gate.verify_and_consume(
        approval_id=approval.approval_id,
        operation_id="OP-2026-000001",
        current_scope_hash=scope.compute_hash()
    )
    assert replay_valid is False
    assert "already been consumed" in replay_reason

def test_approval_expiration(tmp_path):
    # TTL of 0.1 seconds
    gate = ApprovalGate(default_ttl_seconds=0.1)
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=["app.py"])

    approval = gate.create_request(
        operation_id="OP-2026-000002",
        actor="user",
        target="app.py",
        scope=scope,
        requested_actions=["WRITE"],
        ttl_seconds=0.05
    )
    gate.grant(approval.approval_id, actor="lead_architect")

    time.sleep(0.1)

    # Must be rejected due to expiration (INV-006)
    valid, reason = gate.verify_and_consume(
        approval_id=approval.approval_id,
        operation_id="OP-2026-000002",
        current_scope_hash=scope.compute_hash()
    )
    assert valid is False
    assert "expired" in reason.lower()

def test_approval_scope_hash_mismatch(tmp_path):
    gate = ApprovalGate(default_ttl_seconds=60.0)
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=["app.py"])

    approval = gate.create_request(
        operation_id="OP-2026-000003",
        actor="user",
        target="app.py",
        scope=scope,
        requested_actions=["WRITE"]
    )
    gate.grant(approval.approval_id, actor="lead_architect")

    # Tampered scope
    tampered_scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=["app.py", "unapproved.py"])

    valid, reason = gate.verify_and_consume(
        approval_id=approval.approval_id,
        operation_id="OP-2026-000003",
        current_scope_hash=tampered_scope.compute_hash()
    )
    assert valid is False
    assert "Scope mismatch" in reason

def test_approval_replay_via_different_operation(tmp_path):
    """PI-017: Approval consumed for OP-A cannot authorize OP-B."""
    from agos.core.scope import ExecutionScope
    from agos.core.approval import ApprovalGate
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=['a.py'])
    gate = ApprovalGate()
    app = gate.create_request('OP-A', 'dev', 'a.py', scope, ['WRITE'])
    gate.grant(app.approval_id, 'dev')
    ok, _ = gate.verify_and_consume(app.approval_id, 'OP-A', scope.compute_hash())
    assert ok is True
    # Replay with OP-B
    ok2, reason2 = gate.verify_and_consume(app.approval_id, 'OP-B', scope.compute_hash())
    assert ok2 is False
    assert 'consumed' in reason2.lower() or 'CONSUMED' in reason2

def test_policy_requires_consumed_not_granted(tmp_path):
    """INV-039: PolicyEngine must DENY if approval is GRANTED but not CONSUMED."""
    from agos.core.policy import PolicyEngine, PolicyDecision
    from agos.core.state_machine import OperationState
    from agos.core.scope import ExecutionScope
    from agos.core.operation import Operation
    from agos.core.approval import ApprovalGate
    engine = PolicyEngine()
    scope = ExecutionScope(
        workspace_root=str(tmp_path),
        allowed_paths=['app.py'],
        allowed_actions=['WRITE'],
    )
    scope.lock()
    op = Operation(scope=scope, target='app.py')
    gate = ApprovalGate()
    app = gate.create_request(op.operation_id, 'dev', 'app.py', scope, ['WRITE'])
    gate.grant(app.approval_id, 'dev')
    op.approval = app  # GRANTED but NOT consumed
    op.transition_to(OperationState.EVIDENCE)
    op.transition_to(OperationState.PLAN)
    op.transition_to(OperationState.AWAITING_APPROVAL)
    op.transition_to(OperationState.APPROVED)
    op.transition_to(OperationState.EXECUTING)
    res = engine.authorize('WRITE', operation=op, target_path=tmp_path / 'app.py')
    assert res.decision == PolicyDecision.DENY
    assert 'APPROVAL_NOT_CONSUMED' in res.reason_code
