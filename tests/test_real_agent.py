import pytest
from agos.core.agent import AgosAgent
from agos.core.router import ToolRegistry
from agos.core.state_machine import OperationState
from agos.core.operation import Operation
from agos.core.scope import ExecutionScope
from agos.core.approval import ApprovalGate
from agos.security.prompt_guard import ContextFirewall
from agos.tools.modifier import FileModifierTool
from agos.core.verification import VerificationGate
from agos.core.audit import AuditTrail


def test_full_agent_mutation_lifecycle_success(tmp_path):
    ws = tmp_path
    src_dir = ws / "src"
    src_dir.mkdir()
    target_file = src_dir / "app.py"
    target_file.write_text("# initial\n", encoding="utf-8")

    firewall = ContextFirewall()
    modifier = FileModifierTool(workspace_root=ws)
    verifier = VerificationGate()
    audit = AuditTrail()

    registry = ToolRegistry()
    registry.register(modifier)

    raw_prompt = "Dodaj walidację do pliku src/app.py"
    sanitized = firewall.sanitize(raw_prompt)
    assert "[FILTERED_INJECTION]" not in sanitized

    scope = ExecutionScope(
        workspace_root=str(ws),
        allowed_paths=["src/app.py"],
        allowed_actions=["WRITE", "READ"],
    )
    scope.lock()
    op = Operation(scope=scope)
    assert op.state == OperationState.READ_ONLY

    op.transition_to(OperationState.EVIDENCE)
    op.finalize_evidence()

    op.transition_to(OperationState.PLAN)
    op.set_plan("Add validate() function to src/app.py")

    op.transition_to(OperationState.AWAITING_APPROVAL)

    gate = ApprovalGate()
    approval = gate.create_request(
        operation_id=op.operation_id,
        actor="lead_dev",
        target="src/app.py",
        scope=scope,
        requested_actions=["WRITE"],
        plan_hash=op.plan_hash,
        evidence_hash=op.evidence_hash,
    )
    gate.grant(approval.approval_id, actor="lead_dev")
    gate.verify_and_consume(
        approval.approval_id,
        op.operation_id,
        scope.compute_hash(),
        target="src/app.py",
        plan_hash=op.plan_hash,
        evidence_hash=op.evidence_hash,
    )
    op.approval = approval

    op.transition_to(OperationState.APPROVED)
    op.transition_to(OperationState.EXECUTING)

    def llm_mock(_prompt: str) -> dict:
        return {
            "tool_call": {
                "name": "file_modifier",
                "kwargs": {
                    "filepath": "src/app.py",
                    "content": "def validate():\n    return True\n",
                },
            },
            "claim": "Dodano funkcję validate() w src/app.py.",
        }

    agent = AgosAgent(registry=registry, llm_mock=llm_mock)
    statement = agent.run(raw_prompt, operation=op)
    assert len(statement.evidences) == 1
    assert "[SUCCESS]" in statement.evidences[0].raw_data
    assert "def validate():" in target_file.read_text(encoding="utf-8")

    op.transition_to(OperationState.VERIFYING)
    verification_report = verifier.verify(op, files_to_verify=["src/app.py"])
    assert verification_report.passed is True

    op.transition_to(OperationState.COMMIT_AUTHORIZED, verification_passed=True)
    op.transition_to(OperationState.STOP)
    assert op.state == OperationState.STOP

    audit.record(
        operation_id=op.operation_id,
        state=str(op.state),
        action="VERIFY_AND_STOP",
        target="src/app.py",
        result="ALLOW",
        actor="lead_dev",
        scope_hash=op.scope_hash,
        approval_id=approval.approval_id,
        reason="Full lifecycle completed",
    )
    is_valid, _ = audit.verify_integrity()
    assert is_valid is True

