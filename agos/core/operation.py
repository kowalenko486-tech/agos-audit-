"""AGOS 3.1 First-Class Operation Model."""
import hashlib
import json
import time
import threading
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict
from agos.core.state_machine import StateMachine, OperationState
from agos.core.scope import ExecutionScope
from agos.core.approval import Approval

_op_lock = threading.Lock()
_op_counter = 1


def generate_operation_id() -> str:
    global _op_counter
    with _op_lock:
        year = time.strftime("%Y")
        op_id = f"OP-{year}-{_op_counter:06d}"
        _op_counter += 1
        return op_id


class Operation(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    operation_id: str = Field(default_factory=generate_operation_id)
    session_id: str = "default-session"
    target: str = ""
    scope: ExecutionScope
    scope_hash: str = ""
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    plan: Optional[str] = None
    # HIGH-02: plan_hash is computed at plan creation and bound to approval
    plan_hash: str = ""
    # HIGH-03: evidence_hash is computed at evidence-ready stage and bound to approval
    evidence_hash: str = ""
    approval: Optional[Approval] = None
    execution: List[Dict[str, Any]] = Field(default_factory=list)
    verification: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    _state_machine: StateMachine = None

    def __init__(self, **data):
        super().__init__(**data)
        if not self.scope_hash and self.scope:
            self.scope_hash = self.scope.compute_hash()
        self._state_machine = StateMachine(OperationState.READ_ONLY)

    @property
    def state(self) -> OperationState:
        return self._state_machine.current_state

    def transition_to(self, new_state: OperationState, reason: str = "", verification_passed: Optional[bool] = None) -> OperationState:
        return self._state_machine.transition_to(new_state, reason, verification_passed=verification_passed)

    def transition_to_failed(self, reason: str) -> None:
        """Transitions operation to FAILED state (terminal security failure)."""
        self.transition_to(OperationState.FAILED, reason)

    def abort(self, reason: str = "") -> OperationState:
        return self._state_machine.abort(reason)

    def add_evidence(self, evidence_data: Dict[str, Any]) -> None:
        self.evidence.append(evidence_data)
        # Recompute evidence hash whenever evidence changes
        self.evidence_hash = self.compute_evidence_hash()

    def record_execution(self, record: Dict[str, Any]) -> None:
        self.execution.append(record)

    def compute_plan_hash(self) -> str:
        """
        HIGH-02: Deterministic SHA-256 of the canonical plan string.
        Returns empty string if no plan set.
        """
        if not self.plan:
            return ""
        encoded = self.plan.strip().encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def compute_evidence_hash(self) -> str:
        """
        HIGH-03: Deterministic SHA-256 of canonicalized evidence list.
        Sorted by source then raw_data to ensure stability.
        Returns empty string if no evidence.
        """
        if not self.evidence:
            return ""
        # Canonical form: sort list for determinism, then JSON-encode
        canonical = sorted(
            self.evidence,
            key=lambda e: (str(e.get("source", "")), str(e.get("raw_data", "")))
        )
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def set_plan(self, plan_text: str) -> str:
        """Sets plan text and computes+stores plan_hash. Returns the hash."""
        self.plan = plan_text
        self.plan_hash = self.compute_plan_hash()
        return self.plan_hash

    def finalize_evidence(self) -> str:
        """Computes and stores evidence_hash. Returns the hash."""
        self.evidence_hash = self.compute_evidence_hash()
        return self.evidence_hash
