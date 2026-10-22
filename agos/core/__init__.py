"""AGOS 3.1 Core Architecture Package."""
from agos.core.models import Evidence, VerifiedStatement
from agos.core.provenance import TrustedTool, generate_provenance_hash, verify_provenance_hash
from agos.core.state_machine import OperationState, StateMachine, StateTransitionError
from agos.core.scope import ExecutionScope, ScopeLockError
from agos.core.approval import Approval, ApprovalGate, ApprovalStatus, approval_gate
from agos.core.operation import Operation, generate_operation_id
from agos.core.policy import PolicyEngine, PolicyDecision, PolicyResult, policy_engine
from agos.core.verification import VerificationGate, VerificationResult, verification_gate
from agos.core.audit import AuditTrail, AuditEvent, audit_trail
from agos.core.router import ToolRegistry
from agos.core.agent import AgosAgent

__all__ = [
    "Evidence",
    "VerifiedStatement",
    "TrustedTool",
    "generate_provenance_hash",
    "verify_provenance_hash",
    "OperationState",
    "StateMachine",
    "StateTransitionError",
    "ExecutionScope",
    "ScopeLockError",
    "Approval",
    "ApprovalGate",
    "ApprovalStatus",
    "approval_gate",
    "Operation",
    "generate_operation_id",
    "PolicyEngine",
    "PolicyDecision",
    "PolicyResult",
    "policy_engine",
    "VerificationGate",
    "VerificationResult",
    "verification_gate",
    "AuditTrail",
    "AuditEvent",
    "audit_trail",
    "ToolRegistry",
    "AgosAgent",
]
