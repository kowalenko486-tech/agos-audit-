"""Tests for AGOS 3.1 Git Safety Controls and Separate Push Capability."""
import subprocess
import pytest
from pathlib import Path
from agos.tools.git import GitCommitTool, GitPushTool
from agos.core.operation import Operation
from agos.core.scope import ExecutionScope
from agos.core.approval import ApprovalGate
from agos.core.state_machine import OperationState

def test_git_commit_rejects_dot_and_wildcard():
    tool = GitCommitTool()

    # Rejection of "."
    res1 = tool.execute(files=".", message="commit dot")
    assert "[COMMIT DENIED]" in res1
    assert "entire directory ('.')" in res1

    # Rejection of wildcard "*"
    res2 = tool.execute(files=["*.py"], message="commit wildcard")
    assert "[COMMIT DENIED]" in res2

    # Rejection of empty list
    res3 = tool.execute(files=[], message="empty")
    assert "[COMMIT DENIED]" in res3

def test_git_commit_denied_without_passed_verification(tmp_path):
    ws = tmp_path
    tool = GitCommitTool(workspace_root=ws)

    # Setup git repo in tmp_path
    subprocess.run(["git", "init"], cwd=str(ws), capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=str(ws), check=True)
    subprocess.run(["git", "config", "user.email", "test@agos.local"], cwd=str(ws), check=True)

    bad_file = ws / "broken.py"
    bad_file.write_text("def broken_syntax(:\n", encoding="utf-8") # Syntax error!

    scope = ExecutionScope(workspace_root=str(ws), allowed_paths=["broken.py"], allowed_actions=["WRITE", "COMMIT"])
    scope.lock()
    op = Operation(scope=scope)

    op.transition_to(OperationState.EVIDENCE)
    op.transition_to(OperationState.PLAN)
    op.transition_to(OperationState.AWAITING_APPROVAL)

    gate = ApprovalGate()
    approval = gate.create_request(op.operation_id, "lead", "broken.py", scope, ["WRITE", "COMMIT"])
    gate.grant(approval.approval_id, "lead")
    op.approval = approval
    op.transition_to(OperationState.APPROVED)
    op.transition_to(OperationState.EXECUTING)
    op.transition_to(OperationState.VERIFYING)

    # Attempt commit when verification has syntax violation
    res = tool.execute(files=["broken.py"], message="broken commit", operation=op)
    assert "[COMMIT DENIED]" in res
    assert "INV-003" in res or "Verification Gate failed" in res

def test_git_push_strictly_denied():
    push_tool = GitPushTool()
    res = push_tool.execute()
    assert "[PUSH DENIED]" in res
    assert "INV-010" in res
