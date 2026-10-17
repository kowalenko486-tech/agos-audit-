"""Tests for AGOS 3.1 State Machine and Transition Invariants."""
import pytest
from agos.core.state_machine import StateMachine, OperationState, StateTransitionError

def test_valid_lifecycle_transitions():
    sm = StateMachine(OperationState.READ_ONLY)
    assert sm.current_state == OperationState.READ_ONLY

    sm.transition_to(OperationState.EVIDENCE)
    assert sm.current_state == OperationState.EVIDENCE

    sm.transition_to(OperationState.PLAN)
    assert sm.current_state == OperationState.PLAN

    sm.transition_to(OperationState.AWAITING_APPROVAL)
    assert sm.current_state == OperationState.AWAITING_APPROVAL

    sm.transition_to(OperationState.APPROVED)
    assert sm.current_state == OperationState.APPROVED

    sm.transition_to(OperationState.EXECUTING)
    assert sm.current_state == OperationState.EXECUTING

    sm.transition_to(OperationState.VERIFYING)
    assert sm.current_state == OperationState.VERIFYING

    sm.transition_to(OperationState.COMMIT_AUTHORIZED, verification_passed=True)
    assert sm.current_state == OperationState.COMMIT_AUTHORIZED

    sm.transition_to(OperationState.STOP)
    assert sm.current_state == OperationState.STOP


def test_forbidden_transition_read_only_to_executing():
    sm = StateMachine(OperationState.READ_ONLY)
    with pytest.raises(StateTransitionError):
        sm.transition_to(OperationState.EXECUTING)
    # Fail closed: transitions directly to ABORT
    assert sm.current_state == OperationState.ABORT

def test_forbidden_transition_plan_to_executing():
    sm = StateMachine(OperationState.PLAN)
    with pytest.raises(StateTransitionError):
        sm.transition_to(OperationState.EXECUTING)
    assert sm.current_state == OperationState.ABORT

def test_forbidden_transition_executing_to_commit():
    sm = StateMachine(OperationState.EXECUTING)
    with pytest.raises(StateTransitionError):
        sm.transition_to(OperationState.COMMIT_AUTHORIZED)
    assert sm.current_state == OperationState.ABORT

def test_forbidden_transition_verifying_to_executing():
    sm = StateMachine(OperationState.VERIFYING)
    with pytest.raises(StateTransitionError):
        sm.transition_to(OperationState.EXECUTING)
    assert sm.current_state == OperationState.ABORT

def test_abort_from_any_active_state():
    sm = StateMachine(OperationState.PLAN)
    sm.abort("Emergency security stop")
    assert sm.current_state == OperationState.ABORT

    # Terminal state: cannot transition further
    with pytest.raises(StateTransitionError):
        sm.transition_to(OperationState.READ_ONLY)

def test_commit_authorized_requires_verification_passed():
    from agos.core.scope import ExecutionScope
    from agos.core.operation import Operation
    from agos.core.state_machine import OperationState, StateTransitionError
    import pytest
    scope = ExecutionScope(workspace_root='.', allowed_paths=['app.py'])
    op = Operation(scope=scope)
    # Walk to VERIFYING
    for state in [OperationState.EVIDENCE, OperationState.PLAN, 
                  OperationState.AWAITING_APPROVAL, OperationState.APPROVED,
                  OperationState.EXECUTING, OperationState.VERIFYING]:
        op.transition_to(state)
    # Try to commit without passing verification_passed=True
    with pytest.raises(StateTransitionError):
        op.transition_to(OperationState.COMMIT_AUTHORIZED, verification_passed=False)
    with pytest.raises(StateTransitionError):
        op.transition_to(OperationState.COMMIT_AUTHORIZED)  # Default is None -> also denied

def test_commit_authorized_succeeds_with_verification_passed():
    from agos.core.scope import ExecutionScope
    from agos.core.operation import Operation
    from agos.core.state_machine import OperationState
    scope = ExecutionScope(workspace_root='.', allowed_paths=['app.py'])
    op = Operation(scope=scope)
    for state in [OperationState.EVIDENCE, OperationState.PLAN,
                  OperationState.AWAITING_APPROVAL, OperationState.APPROVED,
                  OperationState.EXECUTING, OperationState.VERIFYING]:
        op.transition_to(state)
    op.transition_to(OperationState.COMMIT_AUTHORIZED, verification_passed=True)
    assert op.state == OperationState.COMMIT_AUTHORIZED

def test_failed_state_is_terminal():
    from agos.core.scope import ExecutionScope
    from agos.core.operation import Operation
    from agos.core.state_machine import OperationState, StateTransitionError
    import pytest
    scope = ExecutionScope(workspace_root='.', allowed_paths=['app.py'])
    op = Operation(scope=scope)
    op.transition_to(OperationState.EVIDENCE)
    op.transition_to_failed('Security gate failure')
    with pytest.raises(StateTransitionError):
        op.transition_to(OperationState.STOP)
