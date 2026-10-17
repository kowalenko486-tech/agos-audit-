"""AGOS 3.1 Policy Engine - Centralized Authorization Layer (Fail-Closed)."""
from enum import Enum
from pathlib import Path
from typing import Optional, Union, Dict, Any
from pydantic import BaseModel
from agos.security.capabilities import Capability
from agos.security.sensitive_files import is_sensitive_path
from agos.security.paths import resolve_and_validate_path, SecurityPathError
from agos.core.state_machine import OperationState
from agos.core.operation import Operation
from agos.core.approval import ApprovalStatus
from agos.core.audit import audit_trail


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REQUIRE_VERIFICATION = "REQUIRE_VERIFICATION"

    def __str__(self) -> str:
        return self.value


class PolicyResult(BaseModel):
    decision: PolicyDecision
    reason: str
    reason_code: str = ""
    operation_id: str = ""
    scope_id: str = ""
    approval_id: Optional[str] = None


class PolicyEngine:
    """
    Centralized, fail-closed authorization engine for AGOS 3.1.
    All tool executions and state actions MUST be authorized by PolicyEngine.
    """

    def __init__(self, fail_closed: bool = True):
        self.fail_closed = fail_closed

    def authorize(
        self,
        capability: Union[Capability, str, Any],
        operation: Optional[Operation] = None,
        target_path: Optional[Union[str, Path]] = None,
        actor: str = "system",
        **kwargs
    ) -> PolicyResult:
        """
        Evaluates policy against requested capability, operation state, scope, and target.
        Any unexpected exception results in DENY (Fail Closed).
        """
        op_id = operation.operation_id if operation else "NO-OP"
        scope_hash = operation.scope_hash if operation else ""
        approval_id = operation.approval.approval_id if (operation and operation.approval) else None

        try:
            if not capability:
                raise ValueError("Capability cannot be None or empty.")

            if isinstance(capability, str):
                cap = Capability(capability)
            elif isinstance(capability, Capability):
                cap = capability
            else:
                raise TypeError(f"Invalid capability type: {type(capability)}")

            return self._evaluate_rules(
                cap=cap,
                operation=operation,
                target_path=target_path,
                actor=actor,
                **kwargs
            )
        except Exception as e:
            # FAIL CLOSED
            reason = f"Policy Engine Evaluation Error: {str(e)} (FAIL CLOSED -> DENY)"
            audit_trail.record(
                operation_id=op_id,
                state=str(operation.state) if operation else "UNKNOWN",
                action=str(capability or "UNKNOWN"),
                target=str(target_path or ""),
                result="DENY",
                actor=actor,
                scope_hash=scope_hash,
                approval_id=approval_id,
                reason=reason,
            )
            return PolicyResult(
                decision=PolicyDecision.DENY,
                reason=reason,
                reason_code="POLICY_ERROR",
                operation_id=op_id,
                scope_id=scope_hash,
                approval_id=approval_id,
            )

    def _evaluate_rules(
        self,
        cap: Capability,
        operation: Optional[Operation],
        target_path: Optional[Union[str, Path]],
        actor: str,
        **kwargs
    ) -> PolicyResult:
        op_id = operation.operation_id if operation else "NO-OP"
        scope_hash = operation.scope_hash if operation else ""
        approval_id = operation.approval.approval_id if (operation and operation.approval) else None
        current_state = operation.state if operation else OperationState.READ_ONLY

        # RULE 0: Push and Deploy are strictly DENIED by default
        if cap == Capability.PUSH:
            return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                              "INV-010: Remote push is forbidden without separate external push authorization.",
                              "NO_PUSH_APPROVAL")
        if cap == Capability.DEPLOY:
            return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                              "Deployment capability is strictly forbidden.",
                              "NO_DEPLOY_APPROVAL")

        # RULE 1: Read-only operations without an explicit operation container
        if not operation:
            if cap in (Capability.READ, Capability.ANALYZE):
                # Basic read within workspace can be allowed if target safe
                if target_path and is_sensitive_path(target_path):
                    return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                      f"INV-013: Access to sensitive path '{target_path}' is denied.",
                                      "SENSITIVE_FILE")
                return self._allow(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                   "Read-only action allowed without active operation.")

            # INV-023: Direct tool mutation without operation context — DENY
            if Capability.is_mutation(cap):
                return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                  "INV-001/INV-023: Mutation requires an active operation container. "
                                  "Direct tool bypass is forbidden.",
                                  "DIRECT_TOOL_BYPASS")
            return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                              "INV-001: Mutation requires an active operation container.",
                              "APPROVAL_REQUIRED")

        # RULE 2: Terminal or Aborted states
        if current_state in (OperationState.ABORT, OperationState.STOP):
            return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                              f"Operation is in terminal state: {current_state}.",
                              "POLICY_ERROR")

        # RULE 3: Sensitive File Check
        if target_path:
            if is_sensitive_path(target_path):
                return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                  f"INV-013: Access or mutation of sensitive file '{target_path}' is denied.",
                                  "SENSITIVE_FILE")

            # Workspace Boundary Check
            try:
                resolved_ws = Path(operation.scope.workspace_root).resolve()
                resolve_and_validate_path(target_path, resolved_ws)
            except SecurityPathError as spe:
                return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                  f"INV-002: Workspace boundary violation: {spe}",
                                  "WORKSPACE_ESCAPE")

        # RULE 4: State-Capability Compatibility
        if current_state in (OperationState.READ_ONLY, OperationState.EVIDENCE, OperationState.PLAN):
            if Capability.is_mutation(cap):
                return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                  f"INV-009: Mutation '{cap}' is prohibited in analysis state '{current_state}'.",
                                  "READ_ONLY")
            return self._allow(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                               f"Analysis action '{cap}' allowed in '{current_state}'.")

        if current_state == OperationState.AWAITING_APPROVAL:
            return PolicyResult(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                reason="Operation is awaiting explicit approval.",
                reason_code="APPROVAL_REQUIRED",
                operation_id=op_id,
                scope_id=scope_hash,
                approval_id=approval_id,
            )

        if current_state == OperationState.EXECUTING:
            if not Capability.is_mutation(cap):
                return self._allow(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                   "Read/Analyze permitted during execution phase.")

            # Mutation in EXECUTING: full approval + scope + target + plan + evidence checks

            # 1. Approval existence
            if not operation.approval:
                return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                  "INV-001: Execution mutation attempted without an approval record.",
                                  "APPROVAL_REQUIRED")

            # INV-039: APPROVAL_CONSUMPTION_ATOMIC
            # Require that approval was atomically consumed via ApprovalGate.verify_and_consume()
            # GRANTED status is not sufficient — approval MUST be CONSUMED before execution.
            # This prevents replay: consumed approval cannot be reused for a different operation.
            if operation.approval.status != ApprovalStatus.CONSUMED:
                return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                  f"INV-039: Approval must be verified and consumed via "
                                  f"ApprovalGate.verify_and_consume() before execution. "
                                  f"Current status: {operation.approval.status}. "
                                  f"[APPROVAL_NOT_CONSUMED]",
                                  "APPROVAL_NOT_CONSUMED")

            # 2. Scope Lock & Hash Check
            if not operation.scope.is_locked:
                return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                  "INV-007: Scope must be locked prior to execution.",
                                  "SCOPE_MISMATCH")

            if operation.scope.compute_hash() != operation.approval.scope_hash:
                return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                  "INV-007: Approved scope hash mismatch (Scope changed) [SCOPE_HASH_MISMATCH].",
                                  "SCOPE_HASH_MISMATCH")

            # 3. HIGH-01: Exact target binding check
            if target_path is not None:
                try:
                    resolved_ws = Path(operation.scope.workspace_root).resolve()
                    resolved_target = resolve_and_validate_path(target_path, resolved_ws)
                    resolved_target_str = str(resolved_target).replace("\\", "/").lower()

                    # Normalize the approval target for comparison
                    approval_target_raw = str(operation.approval.target)
                    # approval.target may be relative — resolve it
                    if not Path(approval_target_raw).is_absolute():
                        approval_target_resolved = (resolved_ws / approval_target_raw).resolve()
                    else:
                        approval_target_resolved = Path(approval_target_raw).resolve()
                    approval_target_str = str(approval_target_resolved).replace("\\", "/").lower()

                    if approval_target_str != resolved_target_str:
                        return self._deny(
                            op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                            f"INV-014: Target mismatch — approval is for '{operation.approval.target}', "
                            f"requested '{target_path}' [APPROVAL_TARGET_MISMATCH].",
                            "TARGET_MISMATCH",
                        )
                except SecurityPathError as spe:
                    return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                      f"INV-002: Target path resolution failed: {spe}",
                                      "WORKSPACE_ESCAPE")

            # 4. Scope Path Check
            if target_path:
                if not operation.scope.is_path_in_scope(target_path):
                    return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                      f"INV-002: Target path '{target_path}' is outside approved scope.",
                                      "SCOPE_MISMATCH")

            # 5. HIGH-02: Plan hash integrity
            if operation.approval.plan_hash and operation.plan_hash:
                if operation.plan_hash != operation.approval.plan_hash:
                    return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                      "INV-015: Plan hash mismatch — plan was modified after approval "
                                      "[PLAN_HASH_MISMATCH].",
                                      "PLAN_HASH_MISMATCH")

            # 6. HIGH-03: Evidence hash integrity
            if operation.approval.evidence_hash and operation.evidence_hash:
                current_ev_hash = operation.compute_evidence_hash()
                if current_ev_hash != operation.approval.evidence_hash:
                    return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                      "INV-016: Evidence hash mismatch — evidence was modified after approval "
                                      "[EVIDENCE_HASH_MISMATCH].",
                                      "EVIDENCE_HASH_MISMATCH")

            # 7. Action in allowed actions
            if str(cap) not in operation.scope.allowed_actions:
                return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                  f"Action '{cap}' is not among allowed actions: {operation.scope.allowed_actions}",
                                  "SCOPE_MISMATCH")

            return self._allow(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                               "Execution authorized under approved scope.")

        if current_state == OperationState.VERIFYING:
            if Capability.is_mutation(cap):
                return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                  "Mutation is strictly prohibited during verification.",
                                  "VERIFICATION_REQUIRED")
            return self._allow(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                               "Verification analysis allowed.")

        if current_state == OperationState.COMMIT_AUTHORIZED:
            if cap == Capability.COMMIT:
                return self._allow(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                   "Commit authorized following verified execution.")
            elif not Capability.is_mutation(cap):
                return self._allow(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                   "Read allowed during commit phase.")
            else:
                return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                                  f"Action '{cap}' forbidden in COMMIT_AUTHORIZED state.",
                                  "POLICY_ERROR")

        return self._deny(op_id, current_state, cap, target_path, scope_hash, approval_id, actor,
                          f"Unknown state or capability: {current_state} / {cap}",
                          "POLICY_ERROR")

    def _allow(self, op_id, state, cap, target, scope_hash, approval_id, actor, reason) -> PolicyResult:
        audit_trail.record(
            operation_id=op_id,
            state=str(state),
            action=str(cap),
            target=str(target or ""),
            result="ALLOW",
            actor=actor,
            scope_hash=scope_hash,
            approval_id=approval_id,
            reason=reason,
        )
        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            reason=reason,
            reason_code="ALLOW",
            operation_id=op_id,
            scope_id=scope_hash,
            approval_id=approval_id,
        )

    def _deny(self, op_id, state, cap, target, scope_hash, approval_id, actor, reason,
              reason_code: str = "POLICY_ERROR") -> PolicyResult:
        audit_trail.record(
            operation_id=op_id,
            state=str(state),
            action=str(cap),
            target=str(target or ""),
            result="DENY",
            actor=actor,
            scope_hash=scope_hash,
            approval_id=approval_id,
            reason=reason,
        )
        return PolicyResult(
            decision=PolicyDecision.DENY,
            reason=reason,
            reason_code=reason_code,
            operation_id=op_id,
            scope_id=scope_hash,
            approval_id=approval_id,
        )


policy_engine = PolicyEngine()
