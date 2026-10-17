"""
AGOS 3.2 Regression Invariant Tests.
These tests verify that the test suite DETECTS security regressions.
They test the invariants that are most likely to be accidentally broken.
"""
import pytest
from pathlib import Path
from agos.core.scope import ExecutionScope
from agos.core.operation import Operation
from agos.core.approval import ApprovalGate, ApprovalStatus
from agos.core.policy import PolicyEngine, PolicyDecision
from agos.core.state_machine import OperationState, StateTransitionError
from agos.security.capabilities import Capability


def test_regression_inv039_policy_requires_consumed_not_granted(tmp_path):
    """REGRESSION: PolicyEngine must require CONSUMED status (not just GRANTED)."""
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
    gate.grant(app.approval_id, 'dev')  # GRANTED but NOT consumed
    op.approval = app
    op.transition_to(OperationState.EVIDENCE)
    op.transition_to(OperationState.PLAN)
    op.transition_to(OperationState.AWAITING_APPROVAL)
    op.transition_to(OperationState.APPROVED)
    op.transition_to(OperationState.EXECUTING)
    # MUST DENY because approval is GRANTED not CONSUMED
    res = engine.authorize(Capability.WRITE, operation=op, target_path=tmp_path / 'app.py')
    assert res.decision == PolicyDecision.DENY, \
        'REGRESSION: PolicyEngine accepted GRANTED approval. Must require CONSUMED.'
    assert 'APPROVAL_NOT_CONSUMED' in res.reason_code


def test_regression_inv001_no_approval_no_mutation(tmp_path):
    """REGRESSION: Operation without approval cannot mutate."""
    engine = PolicyEngine()
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=['app.py'])
    op = Operation(scope=scope)
    res = engine.authorize(Capability.WRITE, operation=op, target_path=tmp_path / 'app.py')
    assert res.decision == PolicyDecision.DENY


def test_regression_inv011_consumed_approval_replay(tmp_path):
    """REGRESSION: Consumed approval cannot be replayed."""
    gate = ApprovalGate()
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=['app.py'])
    app = gate.create_request('OP-1', 'dev', 'app.py', scope, ['WRITE'])
    gate.grant(app.approval_id, 'dev')
    ok1, _ = gate.verify_and_consume(app.approval_id, 'OP-1', scope.compute_hash())
    assert ok1
    ok2, reason = gate.verify_and_consume(app.approval_id, 'OP-1', scope.compute_hash())
    assert ok2 is False, 'REGRESSION: Approval replay succeeded.'


def test_regression_inv003_verify_fail_no_commit(tmp_path):
    """REGRESSION: Failed verification must prevent commit."""
    from agos.tools.git import GitCommitTool
    tool = GitCommitTool(workspace_root=tmp_path)
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=['bad.py'], allowed_actions=['WRITE', 'COMMIT'])
    op = Operation(scope=scope)
    op.transition_to(OperationState.EVIDENCE)
    op.transition_to(OperationState.PLAN)
    op.transition_to(OperationState.AWAITING_APPROVAL)
    op.transition_to(OperationState.APPROVED)
    op.transition_to(OperationState.EXECUTING)
    op.verification = {'passed': False, 'violations': ['Syntax error']}
    res = tool.execute(files=['bad.py'], message='failing commit', operation=op)
    assert '[COMMIT DENIED]' in res, 'REGRESSION: Commit succeeded despite failed verification.'


def test_regression_scope_lock_immutable(tmp_path):
    """REGRESSION: Locked scope cannot be modified."""
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=['app.py'])
    scope.lock()
    with pytest.raises((AttributeError, TypeError)):
        scope.allowed_paths.append('evil.py')


def test_regression_sensitive_file_denied(tmp_path):
    """REGRESSION: Sensitive file access must be denied."""
    engine = PolicyEngine()
    res = engine.authorize(Capability.WRITE, operation=None, target_path=tmp_path / '.env')
    assert res.decision == PolicyDecision.DENY


def test_regression_path_traversal_denied(tmp_path):
    """REGRESSION: Path traversal must be denied."""
    from agos.security.paths import resolve_and_validate_path, SecurityPathError
    ws = tmp_path / 'workspace'
    ws.mkdir()
    with pytest.raises(SecurityPathError):
        resolve_and_validate_path('../../../etc/passwd', ws)


def test_regression_state_machine_illegal_transitions():
    """REGRESSION: Illegal state transitions must raise StateTransitionError."""
    scope = ExecutionScope(workspace_root='.', allowed_paths=['app.py'])
    op = Operation(scope=scope)
    with pytest.raises(StateTransitionError):
        op.transition_to(OperationState.EXECUTING)  # Skip required states


def test_regression_push_always_denied():
    """REGRESSION: PUSH must always be denied without explicit push approval."""
    engine = PolicyEngine()
    res = engine.authorize(Capability.PUSH, operation=None)
    assert res.decision == PolicyDecision.DENY


def test_regression_deploy_always_denied():
    """REGRESSION: DEPLOY must always be denied."""
    engine = PolicyEngine()
    res = engine.authorize(Capability.DEPLOY, operation=None)
    assert res.decision == PolicyDecision.DENY


def test_regression_fail_closed_on_exception():
    """REGRESSION: PolicyEngine must DENY on any exception."""
    engine = PolicyEngine()
    res = engine.authorize(capability=None, operation=None)
    assert res.decision == PolicyDecision.DENY
    assert 'FAIL CLOSED' in res.reason
