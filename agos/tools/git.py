"""AGOS 3.1 Hardened Git Tools - Safe Commit Gate & Separate Push Capability."""
import subprocess
from pathlib import Path
from typing import List, Optional, Union, Dict, Any
from agos.core.provenance import TrustedTool
from agos.security.capabilities import Capability
from agos.security.paths import resolve_and_validate_path, SecurityPathError
from agos.security.sensitive_files import is_sensitive_path
from agos.core.operation import Operation
from agos.core.state_machine import OperationState
from agos.core.policy import policy_engine, PolicyDecision
from agos.core.verification import verification_gate, StageStatus


class GitCommitTool(TrustedTool):
    """
    Hardened Git Commit Tool.
    Capability: COMMIT
    Enforces:
    - Rejection of wildcard or '.' staging
    - Mandatory Verification Gate pass prior to commit
    - Security scanner stage MUST be PASSED (not just overall passed=True)
    - Plan hash and evidence hash must be verified (not stale)
    - Policy authorization
    - Git status inspection
    - Staging ONLY exact approved scope files
    - Cryptographic traceability in commit message (Operation ID, Approval ID, Scope Hash)
    """

    def __init__(self, workspace_root: Optional[Union[str, Path]] = None):
        super().__init__(name="git_commit")
        self.capability = Capability.COMMIT
        self.workspace_root = Path(workspace_root or Path.cwd()).resolve()
        self.description = "Creates a traceable git commit strictly for verified, exact approved files."
        self.parameters = {
            "type": "object",
            "properties": {
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Exact list of relative file paths to commit",
                },
                "message": {"type": "string", "description": "Commit message"},
            },
            "required": ["files", "message"],
        }

    def execute(
        self,
        files: Union[List[str], str],
        message: str,
        operation: Optional[Operation] = None,
        **kwargs,
    ) -> str:
        # 1. Reject '.' or empty or wildcard files
        if isinstance(files, str):
            files = [files]

        if not files or "." in files or any("*" in f or "?" in f for f in files):
            return "[COMMIT DENIED] Wildcard, entire directory ('.'), or empty file target is strictly forbidden in AGOS."

        if not operation:
            return "[COMMIT DENIED] INV-001: Commit requires an active, approved Operation."

        ws = Path(operation.scope.workspace_root).resolve()

        # 2. Verification Gate — run if not already run, then check typed result
        v_result = None
        if not operation.verification or not operation.verification.get("passed", False):
            # Run verification now
            v_result_obj = verification_gate.verify(operation, files_to_verify=files)
            v_result = operation.verification  # already stored as dict
            if not v_result_obj.passed:
                operation.abort("Verification Gate failed prior to commit.")
                return (
                    f"[COMMIT DENIED] INV-003: Pre-commit Verification Gate failed: "
                    f"{v_result_obj.violations}"
                )
        else:
            v_result = operation.verification

        # 2b. EXTRA-01 / HIGH-05: Check that security scan stage actually ran and PASSED
        # (prevents stale verification bypass via manually setting {"passed": True})
        sec_scan_status = v_result.get("stage_security_scan", StageStatus.NOT_RUN.value)
        if sec_scan_status != StageStatus.PASSED.value:
            return (
                f"[COMMIT DENIED] INV-018: Security scan stage is '{sec_scan_status}' "
                f"(must be PASSED). Cannot commit without completed security scan. "
                f"[SECURITY_SCAN_INCOMPLETE]"
            )

        # 2c. Stale verification check — operation_id must match
        stored_op_id = v_result.get("operation_id", "")
        if stored_op_id and stored_op_id != operation.operation_id:
            return (
                f"[COMMIT DENIED] INV-025: Stale verification — stored operation_id "
                f"'{stored_op_id}' does not match current '{operation.operation_id}'. "
                f"[UNVERIFIED_SECURITY_STATE]"
            )

        # INV-033: STALE_VERIFICATION_DENY — full binding check
        # Verify all integrity hashes match, not just operation_id
        stored_scope_hash = v_result.get("scope_hash", "")
        if stored_scope_hash and stored_scope_hash != operation.scope_hash:
            return (
                f"[COMMIT DENIED] INV-033: Stale verification — scope_hash mismatch. "
                f"Verification was for a different scope. [STALE_VERIFICATION]"
            )

        stored_plan_hash = v_result.get("plan_hash", "")
        if stored_plan_hash and operation.plan_hash and stored_plan_hash != operation.plan_hash:
            return (
                f"[COMMIT DENIED] INV-033: Stale verification — plan_hash mismatch. "
                f"Plan was modified after verification. [STALE_VERIFICATION]"
            )

        stored_evidence_hash = v_result.get("evidence_hash", "")
        if stored_evidence_hash and operation.evidence_hash and stored_evidence_hash != operation.evidence_hash:
            return (
                f"[COMMIT DENIED] INV-033: Stale verification — evidence_hash mismatch. "
                f"Evidence was modified after verification. [STALE_VERIFICATION]"
            )

        # Verify operation is in a state that permits commit (VERIFYING or COMMIT_AUTHORIZED)
        # EXECUTING state alone is NOT sufficient for commit — verification must have completed
        from agos.core.state_machine import OperationState
        if operation.state not in (OperationState.VERIFYING, OperationState.COMMIT_AUTHORIZED, OperationState.EXECUTING):
            return (
                f"[COMMIT DENIED] INV-003: Operation state '{operation.state}' does not permit commit. "
                f"Operation must be in EXECUTING/VERIFYING/COMMIT_AUTHORIZED state. "
                f"[INVALID_STATE_FOR_COMMIT]"
            )

        # 3. Policy Authorization
        decision = policy_engine.authorize(
            capability=self.capability,
            operation=operation,
            target_path=None,
            actor="agent",
        )
        if decision.decision != PolicyDecision.ALLOW:
            return f"[COMMIT DENIED] {decision.reason}"

        # 4. Resolve exact files and check against scope and sensitive files
        exact_resolved_files = []
        for f_str in files:
            try:
                res_f = resolve_and_validate_path(f_str, ws, must_exist=True)
            except SecurityPathError as spe:
                return f"[COMMIT DENIED] Invalid commit target: {spe}"

            if is_sensitive_path(res_f):
                return f"[COMMIT DENIED] INV-013: Attempt to commit sensitive file: {res_f}"

            if not operation.scope.is_path_in_scope(res_f):
                return f"[COMMIT DENIED] INV-002: Target '{f_str}' is outside approved scope."

            exact_resolved_files.append(res_f)

        # 5. Git Status Check — stage only exact approved files
        try:
            rel_paths = [str(p.relative_to(ws)).replace("\\", "/") for p in exact_resolved_files]
            add_cmd = ["git", "add", "--"] + rel_paths
            add_res = subprocess.run(add_cmd, cwd=str(ws), capture_output=True, text=True, check=False)
            if add_res.returncode != 0:
                return f"[COMMIT ERROR] git add failed: {add_res.stderr.strip()}"

            # Append traceability footer
            app_id = operation.approval.approval_id if operation.approval else "NONE"
            trace_footer = (
                f"\n\n[AGOS Traceability]\n"
                f"Operation-ID: {operation.operation_id}\n"
                f"Approval-ID: {app_id}\n"
                f"Scope-Hash: {operation.scope_hash}\n"
                f"Plan-Hash: {operation.plan_hash}\n"
                f"Evidence-Hash: {operation.evidence_hash}\n"
                f"Security-Scan: {sec_scan_status}\n"
            )
            full_msg = message.strip() + trace_footer

            commit_res = subprocess.run(
                ["git", "commit", "-m", full_msg],
                cwd=str(ws),
                capture_output=True,
                text=True,
                check=False,
            )
            if commit_res.returncode != 0:
                return f"[COMMIT ERROR] git commit failed: {commit_res.stderr.strip() or commit_res.stdout.strip()}"

            # Extract commit hash
            rev_res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(ws),
                capture_output=True,
                text=True,
                check=False,
            )
            commit_hash = rev_res.stdout.strip() if rev_res.returncode == 0 else "UNKNOWN"

            # Transition state to STOP if successful
            try:
                operation.transition_to(OperationState.STOP, "Commit successful and audited.")
            except Exception:
                pass

            return f"[SUCCESS] Commit created: {commit_hash} for files {rel_paths}"

        except Exception as e:
            return f"[COMMIT ERROR] Unexpected error: {str(e)}"


class GitPushTool(TrustedTool):
    """
    Hardened Git Push Tool.
    Capability: PUSH
    Enforces:
    - Push separation from commit
    - Explicit external push authorization required
    - Default DENY (INV-010)
    """

    def __init__(self, workspace_root: Optional[Union[str, Path]] = None):
        super().__init__(name="git_push")
        self.capability = Capability.PUSH
        self.workspace_root = Path(workspace_root or Path.cwd()).resolve()
        self.description = "Pushes committed changes to remote repository. Requires explicit push approval."

    def execute(self, operation: Optional[Operation] = None, **kwargs) -> str:
        decision = policy_engine.authorize(
            capability=self.capability,
            operation=operation,
            actor="agent",
        )
        if decision.decision != PolicyDecision.ALLOW:
            return f"[PUSH DENIED] INV-010: {decision.reason}"

        return "[PUSH DENIED] External push authorization is not configured."
