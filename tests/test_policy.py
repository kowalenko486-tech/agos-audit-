"""Tests for AGOS 3.1 Central Policy Engine (Fail-Closed, Capabilities, and Rules)."""
import pytest
from pathlib import Path
from agos.core.policy import PolicyEngine, PolicyDecision
from agos.core.operation import Operation
from agos.core.scope import ExecutionScope
from agos.core.approval import ApprovalGate
from agos.core.state_machine import OperationState
from agos.security.capabilities import Capability

def test_policy_read_only_blocks_mutation(tmp_path):
    engine = PolicyEngine()
    ws = str(tmp_path)
    scope = ExecutionScope(workspace_root=ws, allowed_paths=["app.py"])
    op = Operation(scope=scope)

    # In READ_ONLY state, WRITE capability must be denied (INV-009)
    result = engine.authorize(
        capability=Capability.WRITE,
        operation=op,
        target_path=tmp_path / "app.py"
    )
    assert result.decision == PolicyDecision.DENY
    assert "INV-009" in result.reason

def test_policy_sensitive_path_denied(tmp_path):
    engine = PolicyEngine()
    ws = str(tmp_path)
    scope = ExecutionScope(workspace_root=ws, allowed_paths=[".env"])
    op = Operation(scope=scope)
    op.transition_to(OperationState.EVIDENCE)

    result = engine.authorize(
        capability=Capability.READ,
        operation=op,
        target_path=tmp_path / ".env"
    )
    assert result.decision == PolicyDecision.DENY
    assert "INV-013" in result.reason

def test_policy_push_strictly_denied_by_default(tmp_path):
    engine = PolicyEngine()
    ws = str(tmp_path)
    scope = ExecutionScope(workspace_root=ws, allowed_paths=["app.py"])
    op = Operation(scope=scope)

    result = engine.authorize(
        capability=Capability.PUSH,
        operation=op
    )
    assert result.decision == PolicyDecision.DENY
    assert "INV-010" in result.reason

def test_policy_fail_closed_on_error():
    engine = PolicyEngine()
    # Passing invalid parameters or malformed inputs causes exception caught by engine
    result = engine.authorize(
        capability="UNKNOWN_CAPABILITY_XYZ",
        operation=None
    )
    assert result.decision == PolicyDecision.DENY
    assert "FAIL CLOSED" in result.reason
