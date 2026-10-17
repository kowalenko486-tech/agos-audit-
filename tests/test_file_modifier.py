"""Tests for AGOS 3.1 Hardened File Modifier Tool."""
import pytest
from pathlib import Path
from agos.tools.modifier import FileModifierTool
from agos.core.operation import Operation
from agos.core.scope import ExecutionScope
from agos.core.approval import ApprovalGate
from agos.core.state_machine import OperationState

def test_file_modifier_atomic_write_and_snapshot(tmp_path):
    ws = tmp_path
    target_file = ws / "module.py"
    target_file.write_text("v1 = 1", encoding="utf-8")

    tool = FileModifierTool(workspace_root=ws)

    # Setup approved operation
    scope = ExecutionScope(
        workspace_root=str(ws),
        allowed_paths=["module.py"],
        allowed_actions=["WRITE", "READ"]
    )
    scope.lock()
    op = Operation(scope=scope)

    # Advance state to EXECUTING
    op.transition_to(OperationState.EVIDENCE)
    op.transition_to(OperationState.PLAN)
    op.transition_to(OperationState.AWAITING_APPROVAL)

    gate = ApprovalGate()
    approval = gate.create_request(
        operation_id=op.operation_id,
        actor="lead_dev",
        target="module.py",
        scope=scope,
        requested_actions=["WRITE"]
    )
    gate.grant(approval.approval_id, actor="lead_dev")
    gate.verify_and_consume(approval.approval_id, op.operation_id, scope.compute_hash(), target="module.py")
    op.approval = approval
    op.transition_to(OperationState.APPROVED)
    op.transition_to(OperationState.EXECUTING)

    # Execute write
    result = tool.execute(
        filepath="module.py",
        content="v2 = 2",
        operation=op
    )
    assert "[SUCCESS]" in result
    assert target_file.read_text(encoding="utf-8") == "v2 = 2"

    # Verify snapshot was created
    snapshot_dir = ws / ".agos_snapshots" / op.operation_id
    assert snapshot_dir.exists()
    snapshots = list(snapshot_dir.glob("*.bak"))
    assert len(snapshots) == 1
    assert snapshots[0].read_text(encoding="utf-8") == "v1 = 1"

def test_file_modifier_denies_without_approval(tmp_path):
    ws = tmp_path
    tool = FileModifierTool(workspace_root=ws)

    scope = ExecutionScope(workspace_root=str(ws), allowed_paths=["app.py"])
    op = Operation(scope=scope) # in READ_ONLY state, no approval

    result = tool.execute(filepath="app.py", content="content", operation=op)
    assert "[POLICY DENIED]" in result

def test_file_modifier_denies_outside_scope(tmp_path):
    ws = tmp_path
    tool = FileModifierTool(workspace_root=ws)

    scope = ExecutionScope(workspace_root=str(ws), allowed_paths=["allowed.py"])
    scope.lock()
    op = Operation(scope=scope)
    op.transition_to(OperationState.EVIDENCE)
    op.transition_to(OperationState.PLAN)
    op.transition_to(OperationState.AWAITING_APPROVAL)

    gate = ApprovalGate()
    approval = gate.create_request(op.operation_id, "dev", "allowed.py", scope, ["WRITE"])
    gate.grant(approval.approval_id, "dev")
    gate.verify_and_consume(approval.approval_id, op.operation_id, scope.compute_hash(), target="allowed.py")
    op.approval = approval
    op.transition_to(OperationState.APPROVED)
    op.transition_to(OperationState.EXECUTING)

    result = tool.execute(filepath="forbidden.py", content="content", operation=op)
    assert "[POLICY DENIED]" in result
    # INV-014 fires first (target mismatch), INV-002 also valid for scope escape
    assert "INV-002" in result or "INV-014" in result or "APPROVAL_TARGET_MISMATCH" in result

def test_file_modifier_denies_oversized_content(tmp_path):
    ws = tmp_path
    tool = FileModifierTool(workspace_root=ws, max_bytes=10) # 10 byte limit
    result = tool.execute(filepath="app.py", content="this content is clearly larger than 10 bytes")
    assert "[POLICY DENIED]" in result
    assert "exceeds limit" in result
