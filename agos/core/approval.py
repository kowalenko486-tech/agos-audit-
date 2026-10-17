"""AGOS 3.1 Approval Gate, Time-bound Approvals, and Replay Protection."""
import time
import threading
import unicodedata
from enum import Enum
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field

def _canonical_target(t: str) -> str:
    """Unicode NFC + separator normalization + lower for cross-platform target binding."""
    t = unicodedata.normalize('NFC', str(t))
    t = t.replace('\\', '/').strip().lower()
    return t

from agos.core.scope import ExecutionScope


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    GRANTED = "GRANTED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"
    REVOKED = "REVOKED"

    def __str__(self) -> str:
        return self.value


class Approval(BaseModel):
    approval_id: str
    operation_id: str
    actor: str
    target: str
    scope_hash: str
    requested_actions: List[str]
    plan_hash: str = ""
    evidence_hash: str = ""
    created_at: float = Field(default_factory=time.time)
    expires_at: float
    status: ApprovalStatus = ApprovalStatus.PENDING

    def is_valid(self, current_time: Optional[float] = None) -> Tuple[bool, str]:
        """
        Validates whether the approval is currently eligible to authorize execution.
        Enforces time-bound validity and unconsumed status.
        NOTE: This method is NOT thread-safe alone. Always call via
        ApprovalGate.verify_and_consume() which holds the gate lock atomically.
        """
        now = time.time() if current_time is None else current_time

        if self.status == ApprovalStatus.CONSUMED:
            return False, "Approval has already been consumed (Replay attack prevented)."

        if self.status == ApprovalStatus.REVOKED:
            return False, "Approval has been explicitly revoked."

        if self.status == ApprovalStatus.REJECTED:
            return False, "Approval was rejected."

        if self.status != ApprovalStatus.GRANTED:
            return False, f"Approval is not in GRANTED state (Current status: {self.status})."

        if now > self.expires_at:
            self.status = ApprovalStatus.EXPIRED
            return False, f"Approval expired at {self.expires_at} (Current time: {now})."

        return True, "Approval is valid."

    def consume(self) -> None:
        """Transitions approval into CONSUMED state to prevent replay."""
        self.status = ApprovalStatus.CONSUMED

    def revoke(self) -> None:
        """Revokes the approval."""
        self.status = ApprovalStatus.REVOKED


class ApprovalGate:
    """Central registry and verification authority for AGOS approvals."""

    def __init__(self, default_ttl_seconds: float = 300.0):  # 5 minutes default TTL
        self._approvals: dict[str, Approval] = {}
        self.default_ttl = default_ttl_seconds
        self._counter = 1
        # CRIT-01 FIX: Single lock protects all approval state mutations.
        # verify_and_consume() holds this lock for the ENTIRE check-and-consume
        # sequence, making replay impossible even under concurrent access.
        self._lock = threading.Lock()

    def create_request(
        self,
        operation_id: str,
        actor: str,
        target: str,
        scope: ExecutionScope,
        requested_actions: List[str],
        plan_hash: str = "",
        evidence_hash: str = "",
        ttl_seconds: Optional[float] = None,
    ) -> Approval:
        """Creates a pending approval request."""
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        now = time.time()
        with self._lock:
            app_id = f"APPROVAL-{time.strftime('%Y')}-{self._counter:06d}"
            self._counter += 1
            approval = Approval(
                approval_id=app_id,
                operation_id=operation_id,
                actor=actor,
                target=target,
                scope_hash=scope.compute_hash(),
                requested_actions=requested_actions,
                plan_hash=plan_hash,
                evidence_hash=evidence_hash,
                created_at=now,
                expires_at=now + ttl,
                status=ApprovalStatus.PENDING,
            )
            self._approvals[app_id] = approval
        return approval

    def grant(self, approval_id: str, actor: str) -> Approval:
        """Grants an explicit approval."""
        with self._lock:
            if approval_id not in self._approvals:
                raise KeyError(f"Approval ID {approval_id} not found.")

            app = self._approvals[approval_id]
            if app.status != ApprovalStatus.PENDING:
                raise RuntimeError(f"Cannot grant approval in state {app.status}.")

            now = time.time()
            if now > app.expires_at:
                app.status = ApprovalStatus.EXPIRED
                raise RuntimeError("Cannot grant expired approval.")

            app.status = ApprovalStatus.GRANTED
            app.actor = actor
            return app

    def verify_and_consume(
        self,
        approval_id: str,
        operation_id: str,
        current_scope_hash: str,
        target: Optional[str] = None,
        plan_hash: Optional[str] = None,
        evidence_hash: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        ATOMIC check-and-consume under gate lock.
        All invariant checks happen inside the lock so no concurrent caller
        can sneak through between check and consume.

        INV-013: APPROVAL_REPLAY -> DENY
        INV-014: APPROVAL_TARGET_MISMATCH -> DENY  (when target provided)
        INV-021: SCOPE_HASH_MISMATCH -> DENY
        INV-015: PLAN_HASH_MISMATCH -> DENY         (when plan_hash provided & stored)
        INV-016: EVIDENCE_HASH_MISMATCH -> DENY     (when evidence_hash provided & stored)
        INV-022: APPROVAL_OPERATION_MISMATCH -> DENY
        """
        with self._lock:
            if approval_id not in self._approvals:
                return False, f"Unknown approval: {approval_id} [APPROVAL_REQUIRED]"

            app = self._approvals[approval_id]

            if app.status == ApprovalStatus.CONSUMED:
                return False, "Approval has already been consumed. [APPROVAL_CONSUMED]"

            # INV-022: Operation binding
            if app.operation_id != operation_id:
                return False, (
                    f"Operation mismatch: approval is for '{app.operation_id}', "
                    f"got '{operation_id}' [APPROVAL_OPERATION_MISMATCH]"
                )

            # INV-021: Scope hash binding
            if app.scope_hash != current_scope_hash:
                return False, (
                    "Scope mismatch: approved scope hash differs from current scope hash "
                    "[SCOPE_HASH_MISMATCH]."
                )

            # INV-014: Target binding (normalized path comparison)
            if target is not None:
                norm_approved = _canonical_target(app.target)
                norm_requested = _canonical_target(target)
                if norm_approved != norm_requested:
                    return False, (
                        f"Target mismatch: approval is for '{app.target}', "
                        f"requested '{target}' [APPROVAL_TARGET_MISMATCH]"
                    )

            # INV-015: Plan hash binding
            if plan_hash is not None and app.plan_hash:
                if app.plan_hash != plan_hash:
                    return False, (
                        "Plan hash mismatch: plan was modified after approval "
                        "[PLAN_HASH_MISMATCH]."
                    )

            # INV-016: Evidence hash binding
            if evidence_hash is not None and app.evidence_hash:
                if app.evidence_hash != evidence_hash:
                    return False, (
                        "Evidence hash mismatch: evidence was modified after approval "
                        "[EVIDENCE_HASH_MISMATCH]."
                    )

            # Status + expiry check — INSIDE lock (prevents TOCTOU)
            valid, reason = app.is_valid()
            if not valid:
                return False, reason

            # ATOMIC consume — no other thread can slip in here
            app.consume()
            return True, "Approval verified and consumed."

    def get_approval(self, approval_id: str) -> Optional[Approval]:
        with self._lock:
            return self._approvals.get(approval_id)
