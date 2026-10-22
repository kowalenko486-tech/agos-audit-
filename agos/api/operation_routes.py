"""Controlled change proposal and mutation execution endpoints.

Enforces:
1. Unified diff computation against current disk content
2. Cryptographic SHA-256 hash binding of proposed payload
3. AST and security pre-screening before approval
4. Exact-payload write via FileModifierTool (atomic + backup)
5. Immediate mandatory VerificationGate execution
"""
import difflib
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from agos.api.state import operations_lock, operations_store, proposals
from agos.core.audit import audit_trail
from agos.core.mutation_intent import MutationIntent, MutationType, DiffPolicy
from agos.core.policy import policy_engine, PolicyDecision
from agos.core.scope import ExecutionScope
from agos.core.state_machine import OperationState
from agos.core.verification import verification_gate
from agos.core.workspace_manager import workspace_manager
from agos.security.capabilities import Capability
from agos.security.paths import resolve_and_validate_path, SecurityPathError
from agos.security.sensitive_files import is_sensitive_path
from agos.tools import inspector
from agos.tools.modifier import FileModifierTool

router = APIRouter()


def _ws() -> Path:
    return Path(workspace_manager.get_current_workspace()).resolve()


class ProposalRequest(BaseModel):
    filepath: str = Field(..., min_length=1, max_length=1024)
    proposed_content: str = Field(..., max_length=1_000_000)
    summary: str = Field(default="Propozycja modyfikacji pliku", max_length=500)


@router.post("/api/operations/{operation_id}/proposal")
async def create_proposal(operation_id: str, req: ProposalRequest):
    """
    Submits a change proposal. Computes unified diff, hashes, and pre-screens content.
    Binds the proposal to the operation before the approval gate.
    """
    ws = _ws()
    with operations_lock:
        op = operations_store.get(operation_id)
        if not op:
            raise HTTPException(status_code=404, detail="Operation not found")

        # Must be in PLAN or EVIDENCE state
        if op.state not in (OperationState.READ_ONLY, OperationState.EVIDENCE, OperationState.PLAN):
            raise HTTPException(
                status_code=400,
                detail=f"Propozycję można złożyć tylko przed zatwierdzeniem (obecny stan: {op.state})"
            )

        try:
            resolved = resolve_and_validate_path(req.filepath, ws, must_exist=False)
        except SecurityPathError as spe:
            raise HTTPException(status_code=403, detail=f"Odmowa ścieżki: {spe}")

        if is_sensitive_path(resolved):
            raise HTTPException(status_code=403, detail="Odmowa: plik wrażliwy (INV-013)")

        rel_path = resolved.relative_to(ws).as_posix()

        # Read original if exists
        orig_content = ""
        if resolved.exists():
            if not resolved.is_file():
                raise HTTPException(status_code=400, detail="Docelowa ścieżka nie jest plikiem")
            try:
                data = inspector.read_text_file(ws, rel_path)
                orig_content = data["content"]
            except Exception as e:
                orig_content = ""

        # Compute unified diff
        orig_lines = orig_content.splitlines(keepends=True)
        new_lines = req.proposed_content.splitlines(keepends=True)
        diff_lines = list(difflib.unified_diff(
            orig_lines,
            new_lines,
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
            lineterm="\n"
        ))
        diff_text = "".join(diff_lines) or "(brak zmian w zawartości)"

        # Count added/removed
        added = sum(1 for ln in diff_lines if ln.startswith("+") and not ln.startswith("+++"))
        removed = sum(1 for ln in diff_lines if ln.startswith("-") and not ln.startswith("---"))

        # Payload hash
        content_bytes = req.proposed_content.encode("utf-8")
        payload_hash = hashlib.sha256(content_bytes).hexdigest()

        # Content pre-screening (findings in proposed content)
        findings = inspector.scan_content(req.proposed_content, rel_path)

        # Set target and plan on operation
        op.target = rel_path
        if not op.scope.is_locked:
            if rel_path not in op.scope.allowed_paths:
                op.scope.add_allowed_path(rel_path)
            if "WRITE" not in op.scope.allowed_actions:
                actions = list(op.scope.allowed_actions)
                actions.append("WRITE")
                op.scope.allowed_actions = actions

        plan_desc = f"{req.summary} | Target: {rel_path} | SHA256: {payload_hash[:16]} | +{added}/-{removed}"
        op.set_plan(plan_desc)

        # Advance lifecycle through legal states to PLAN
        if op.state == OperationState.READ_ONLY:
            op.transition_to(OperationState.EVIDENCE, reason="Zgromadzono dowód z dysku dla propozycji")
        if op.state == OperationState.EVIDENCE:
            op.finalize_evidence()
            op.transition_to(OperationState.PLAN, reason="Ustalono plan i wyliczono diff propozycji")

        # Create MutationIntent
        intent = MutationIntent(
            operation_id=op.operation_id,
            target_files=[rel_path],
            capability="WRITE",
            plan_hash=op.plan_hash,
            allowed_mutation_type=MutationType.ANY,
            diff_policy=DiffPolicy(max_lines_added=added + 50, max_lines_removed=removed + 50),
        ).seal()

        # Save proposal in memory
        proposals[op.operation_id] = {
            "operation_id": op.operation_id,
            "filepath": rel_path,
            "proposed_content": req.proposed_content,
            "original_content": orig_content,
            "diff": diff_text,
            "sha256": payload_hash,
            "lines_added": added,
            "lines_removed": removed,
            "findings": findings,
            "mutation_intent": intent,
        }

        audit_trail.record(
            operation_id=op.operation_id,
            state=str(op.state),
            action="CREATE_PROPOSAL",
            target=rel_path,
            result="SUCCESS",
            actor="engineer_gui",
            reason=f"Proposal created: +{added}/-{removed}, sha256={payload_hash[:16]}"
        )

        return {
            "operation_id": op.operation_id,
            "filepath": rel_path,
            "diff": diff_text,
            "sha256": payload_hash,
            "lines_added": added,
            "lines_removed": removed,
            "findings": findings,
            "plan_hash": op.plan_hash,
        }


@router.get("/api/operations/{operation_id}/proposal")
async def get_proposal(operation_id: str):
    """Retrieves current change proposal for the operation."""
    proposal = proposals.get(operation_id)
    if not proposal:
        raise HTTPException(status_code=404, detail="Brak propozycji dla tej operacji")
    return {
        "operation_id": proposal["operation_id"],
        "filepath": proposal["filepath"],
        "diff": proposal["diff"],
        "sha256": proposal["sha256"],
        "lines_added": proposal["lines_added"],
        "lines_removed": proposal["lines_removed"],
        "findings": proposal["findings"],
    }


@router.post("/api/operations/{operation_id}/apply")
async def apply_proposal(operation_id: str):
    """
    Applies the proposed change strictly under approved scope & state.
    Requires state=EXECUTING (which guarantees consumed approval and locked scope).
    Executes atomic write and runs VerificationGate immediately.
    """
    ws = _ws()
    with operations_lock:
        op = operations_store.get(operation_id)
        if not op:
            raise HTTPException(status_code=404, detail="Operation not found")

        proposal = proposals.get(operation_id)
        if not proposal:
            raise HTTPException(status_code=400, detail="Brak zarejestrowanej propozycji dla tej operacji")

        if op.state != OperationState.EXECUTING:
            raise HTTPException(
                status_code=400,
                detail=f"Zapis wymaga stanu EXECUTING (obecnie: {op.state}). Operacja musi przejść przez bramkę zgody."
            )

        filepath = proposal["filepath"]
        content = proposal["proposed_content"]
        intent = proposal.get("mutation_intent")

        # Execute modification via FileModifierTool
        tool = FileModifierTool(workspace_root=ws)
        write_result = tool.execute(
            filepath=filepath,
            content=content,
            operation=op,
            mutation_intent=intent,
        )

        # Transition to VERIFYING
        try:
            op.transition_to(OperationState.VERIFYING, reason="Zapis wykonany — uruchamianie weryfikacji")
        except Exception:
            pass

        # Execute VerificationGate
        v_result = verification_gate.verify(op, files_to_verify=[filepath])

        # If verification passed, transition to COMMIT_AUTHORIZED or STOP
        if v_result.passed:
            try:
                op.transition_to(OperationState.COMMIT_AUTHORIZED, reason="Weryfikacja zakończona sukcesem", verification_passed=True)
            except Exception:
                pass
        else:
            try:
                op.abort(f"Weryfikacja nie powiodła się: {v_result.violations}")
            except Exception:
                pass

        audit_trail.record(
            operation_id=op.operation_id,
            state=str(op.state),
            action="APPLY_PROPOSAL",
            target=filepath,
            result="PASS" if v_result.passed else "FAIL",
            actor="engineer_gui",
            reason=f"Write complete. Verification passed={v_result.passed}"
        )

        return {
            "operation_id": op.operation_id,
            "target": filepath,
            "write_result": write_result,
            "state": str(op.state),
            "verification_passed": v_result.passed,
            "violations": v_result.violations,
            "findings": v_result.security_findings,
        }
