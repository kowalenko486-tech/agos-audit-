"""AGOS 3.2 MutationIntent — Payload and Diff Authorization.

INV-026: PAYLOAD_NOT_AUTHORIZED_DENY
INV-027: DIFF_NOT_AUTHORIZED_DENY
INV-040: MUTATION_INTENT_REQUIRED

MutationIntent binds an approved operation to:
- Which files may be changed
- What mutation types are allowed
- Maximum diff size
- Forbidden patterns in the payload
- Protected symbol names

Approval alone ('edit app.py') is NOT sufficient.
MutationIntent specifies WHAT KIND of edit is authorized.
"""
import hashlib
import json
import re
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class MutationType(str, Enum):
    """Allowed mutation types."""
    ANY = "ANY"              # No content restriction (default, least restrictive)
    APPEND_ONLY = "APPEND_ONLY"    # Only additions allowed
    MODIFY_FUNCTION = "MODIFY_FUNCTION"  # Only existing function bodies
    FIX_BUG = "FIX_BUG"      # Conservative changes
    REFACTOR = "REFACTOR"     # Restructuring without behavior change

    def __str__(self) -> str:
        return self.value


# High-risk patterns that require explicit approval even when MutationIntent exists
HIGH_RISK_PATTERNS = [
    r"(?i)(secret|password|token|api[_-]?key|credential|private[_-]?key).*=",
    r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    r"(?i)(auth|authenticate|authorize|permission|access[_-]?control)",
    r"(?i)(os\.system|subprocess\.(run|call|Popen)|eval|exec)\s*\(",
    r"(?i)(import\s+os|import\s+subprocess|from\s+os)",
    r"(?i)(chmod|chown|setuid|setgid)",
    r"(?i)(admin|root|superuser|sudo)",
]

COMPILED_HIGH_RISK = [re.compile(p) for p in HIGH_RISK_PATTERNS]


class DiffPolicy(BaseModel):
    """Constraints on the allowed diff."""
    max_lines_added: int = 500
    max_lines_removed: int = 200
    max_files_changed: int = 5
    forbidden_patterns: List[str] = Field(default_factory=list)
    protected_symbols: List[str] = Field(default_factory=list)
    require_high_risk_review: bool = True


class MutationIntent(BaseModel):
    """Authorized mutation intent — binds approval to specific payload constraints.
    
    INV-040: Every mutation operation MUST have a MutationIntent.
    INV-026: Payload not matching intent → DENY.
    INV-027: Diff exceeding authorized scope → DENY.
    """
    operation_id: str
    target_files: List[str]  # Canonicalized allowed target files
    capability: str = "WRITE"
    plan_hash: str = ""
    allowed_mutation_type: MutationType = MutationType.ANY
    diff_policy: DiffPolicy = Field(default_factory=DiffPolicy)
    intent_hash: str = ""

    def compute_intent_hash(self) -> str:
        canonical = {
            "operation_id": self.operation_id,
            "target_files": sorted(self.target_files),
            "capability": self.capability,
            "plan_hash": self.plan_hash,
            "allowed_mutation_type": str(self.allowed_mutation_type),
        }
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def seal(self) -> "MutationIntent":
        """Compute and store intent_hash. Call once after creation."""
        self.intent_hash = self.compute_intent_hash()
        return self


class PayloadAuthorizationResult(BaseModel):
    authorized: bool
    reason: str
    reason_code: str = ""
    high_risk_findings: List[str] = Field(default_factory=list)


def authorize_payload(
    intent: MutationIntent,
    target_file: str,
    proposed_content: str,
    original_content: str = "",
) -> PayloadAuthorizationResult:
    """Validates proposed payload against MutationIntent constraints.
    
    INV-026: PAYLOAD_NOT_AUTHORIZED_DENY
    INV-027: DIFF_NOT_AUTHORIZED_DENY
    
    Returns PayloadAuthorizationResult with authorized=True only if ALL checks pass.
    Fail-closed: any exception → DENY.
    """
    try:
        # 1. Target file must be in authorized target_files
        import unicodedata
        def _norm(p: str) -> str:
            return unicodedata.normalize('NFC', p).replace('\\', '/').strip().lower()
        
        norm_target = _norm(target_file)
        norm_targets = [_norm(t) for t in intent.target_files]
        
        if norm_target not in norm_targets:
            return PayloadAuthorizationResult(
                authorized=False,
                reason=f"INV-026: Target '{target_file}' is not in MutationIntent authorized targets: {intent.target_files}",
                reason_code="PAYLOAD_NOT_AUTHORIZED",
            )

        # 2. High-risk pattern check
        high_risk_findings = []
        for pattern in COMPILED_HIGH_RISK:
            for i, line in enumerate(proposed_content.splitlines(), 1):
                if pattern.search(line):
                    high_risk_findings.append(f"Line {i}: {pattern.pattern[:60]}")
        
        if high_risk_findings and intent.diff_policy.require_high_risk_review:
            return PayloadAuthorizationResult(
                authorized=False,
                reason=f"INV-026: Payload contains high-risk patterns requiring explicit review: {high_risk_findings[:3]}",
                reason_code="PAYLOAD_HIGH_RISK",
                high_risk_findings=high_risk_findings,
            )

        # 3. Forbidden pattern check
        for pattern_str in intent.diff_policy.forbidden_patterns:
            compiled = re.compile(pattern_str, re.IGNORECASE)
            for i, line in enumerate(proposed_content.splitlines(), 1):
                if compiled.search(line):
                    return PayloadAuthorizationResult(
                        authorized=False,
                        reason=f"INV-026: Payload contains forbidden pattern '{pattern_str}' at line {i}.",
                        reason_code="PAYLOAD_FORBIDDEN_PATTERN",
                    )

        # 4. Protected symbol check — must not appear in proposed content (to prevent deletion/modification)
        for symbol in intent.diff_policy.protected_symbols:
            # Check if symbol was in original but removed from proposal
            if symbol in original_content and symbol not in proposed_content:
                return PayloadAuthorizationResult(
                    authorized=False,
                    reason=f"INV-026: Protected symbol '{symbol}' was removed from payload.",
                    reason_code="PAYLOAD_PROTECTED_SYMBOL_REMOVED",
                )

        # 5. Diff size check
        original_lines = set(original_content.splitlines())
        proposed_lines = set(proposed_content.splitlines())
        lines_added = len([l for l in proposed_content.splitlines() if l not in original_lines])
        lines_removed = len([l for l in original_content.splitlines() if l not in proposed_lines])

        if lines_added > intent.diff_policy.max_lines_added:
            return PayloadAuthorizationResult(
                authorized=False,
                reason=f"INV-027: Diff adds {lines_added} lines, exceeds authorized limit {intent.diff_policy.max_lines_added}.",
                reason_code="DIFF_TOO_LARGE",
            )
        if lines_removed > intent.diff_policy.max_lines_removed:
            return PayloadAuthorizationResult(
                authorized=False,
                reason=f"INV-027: Diff removes {lines_removed} lines, exceeds authorized limit {intent.diff_policy.max_lines_removed}.",
                reason_code="DIFF_TOO_LARGE",
            )

        return PayloadAuthorizationResult(
            authorized=True,
            reason="Payload authorized within MutationIntent constraints.",
            reason_code="AUTHORIZED",
        )

    except Exception as e:
        return PayloadAuthorizationResult(
            authorized=False,
            reason=f"INV-026: Payload authorization error (FAIL CLOSED): {e}",
            reason_code="PAYLOAD_AUTH_ERROR",
        )
