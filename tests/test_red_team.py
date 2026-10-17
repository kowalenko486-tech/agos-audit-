"""
AGOS 3.1 Red Team Security Test Suite — R21 through R40.
All tests verify that the system DENIES the attack vector.
Priority: "Did the system refuse?" over "Did the system execute?"
"""
import time
import threading
import pytest
from pathlib import Path

from agos.core.scope import ExecutionScope, ScopeLockError
from agos.core.operation import Operation
from agos.core.approval import ApprovalGate, ApprovalStatus
from agos.core.policy import PolicyEngine, PolicyDecision
from agos.core.verification import VerificationGate, StageStatus
from agos.core.state_machine import OperationState
from agos.core.audit import AuditTrail
from agos.security.capabilities import Capability
from agos.security.sensitive_files import is_sensitive_path
from agos.tools.modifier import FileModifierTool
from agos.tools.git import GitCommitTool
from agos.core.router import ToolRegistry
from agos.core.provenance import TrustedTool, generate_provenance_hash

PROVENANCE_SECRET = "test-provenance-secret-for-pytest-minimum-32-chars!"


@pytest.fixture(autouse=True)
def set_provenance_secret(monkeypatch):
    """All red team tests require the provenance secret."""
    monkeypatch.setenv("AGOS_PROVENANCE_SECRET", PROVENANCE_SECRET)


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_approved_op(tmp_path, target="app.py", extra_allowed=None):
    """Creates an operation in EXECUTING state with a consumed (authorized) approval."""
    allowed = [target] + (extra_allowed or [])
    scope = ExecutionScope(
        workspace_root=str(tmp_path),
        allowed_paths=allowed,
        allowed_actions=["WRITE", "COMMIT"],
    )
    scope.lock()
    op = Operation(scope=scope, target=target)

    gate = ApprovalGate(default_ttl_seconds=60.0)
    approval = gate.create_request(
        operation_id=op.operation_id,
        actor="tester",
        target=target,
        scope=scope,
        requested_actions=["WRITE"],
    )
    gate.grant(approval.approval_id, "tester")

    # INV-039: Consume approval atomically before execution (replay prevention)
    consumed_ok, consume_reason = gate.verify_and_consume(
        approval_id=approval.approval_id,
        operation_id=op.operation_id,
        current_scope_hash=scope.compute_hash(),
        target=target,
    )
    assert consumed_ok, f"Test setup: verify_and_consume failed: {consume_reason}"
    op.approval = approval  # status is now CONSUMED

    op.transition_to(OperationState.EVIDENCE)
    op.transition_to(OperationState.PLAN)
    op.transition_to(OperationState.AWAITING_APPROVAL)
    op.transition_to(OperationState.APPROVED)
    op.transition_to(OperationState.EXECUTING)

    return op, gate, approval


# ── R21: Approval-Operation Mismatch ─────────────────────────────────────────

def test_r21_approval_operation_mismatch(tmp_path):
    """
    R21 — ATTACK: Use approval for OP-A to authorize OP-B.
    EXPECTED: DENY [APPROVAL_OPERATION_MISMATCH]
    """
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=["a.py"])
    gate = ApprovalGate()
    app = gate.create_request("OP-A", "dev", "a.py", scope, ["WRITE"])
    gate.grant(app.approval_id, "dev")

    # Try to consume for a different operation ID
    valid, reason = gate.verify_and_consume(
        approval_id=app.approval_id,
        operation_id="OP-B",
        current_scope_hash=scope.compute_hash(),
    )
    assert valid is False
    assert "APPROVAL_OPERATION_MISMATCH" in reason


# ── R22: Plan Hash Tampering ──────────────────────────────────────────────────

def test_r22_plan_hash_tampering(tmp_path):
    """
    R22 — ATTACK: Modify plan after approval.
    EXPECTED: DENY [PLAN_HASH_MISMATCH] at PolicyEngine.
    """
    engine = PolicyEngine()
    scope = ExecutionScope(
        workspace_root=str(tmp_path),
        allowed_paths=["app.py"],
        allowed_actions=["WRITE"],
    )
    scope.lock()
    op = Operation(scope=scope, target="app.py")
    op.set_plan("Original plan: fix bug in app.py")

    gate = ApprovalGate()
    # Approval includes the original plan hash
    app = gate.create_request(
        op.operation_id, "dev", "app.py", scope, ["WRITE"],
        plan_hash=op.plan_hash
    )
    gate.grant(app.approval_id, "dev")
    gate.verify_and_consume(app.approval_id, op.operation_id, scope.compute_hash(), target="app.py")
    op.approval = app

    op.transition_to(OperationState.EVIDENCE)
    op.transition_to(OperationState.PLAN)
    op.transition_to(OperationState.AWAITING_APPROVAL)
    op.transition_to(OperationState.APPROVED)
    op.transition_to(OperationState.EXECUTING)

    # Attacker modifies plan after approval
    op.set_plan("TAMPERED plan: delete all files")

    result = engine.authorize(
        capability=Capability.WRITE,
        operation=op,
        target_path=tmp_path / "app.py",
    )
    assert result.decision == PolicyDecision.DENY
    assert "PLAN_HASH_MISMATCH" in result.reason


# ── R23: Evidence Hash Tampering ──────────────────────────────────────────────

def test_r23_evidence_hash_tampering(tmp_path):
    """
    R23 — ATTACK: Modify evidence after approval.
    EXPECTED: DENY [EVIDENCE_HASH_MISMATCH] at PolicyEngine.
    """
    engine = PolicyEngine()
    scope = ExecutionScope(
        workspace_root=str(tmp_path),
        allowed_paths=["app.py"],
        allowed_actions=["WRITE"],
    )
    scope.lock()
    op = Operation(scope=scope, target="app.py")
    op.add_evidence({"source": "scan", "raw_data": "original result"})

    gate = ApprovalGate()
    app = gate.create_request(
        op.operation_id, "dev", "app.py", scope, ["WRITE"],
        evidence_hash=op.evidence_hash,
    )
    gate.grant(app.approval_id, "dev")
    gate.verify_and_consume(app.approval_id, op.operation_id, scope.compute_hash(), target="app.py")
    op.approval = app

    op.transition_to(OperationState.EVIDENCE)
    op.transition_to(OperationState.PLAN)
    op.transition_to(OperationState.AWAITING_APPROVAL)
    op.transition_to(OperationState.APPROVED)
    op.transition_to(OperationState.EXECUTING)

    # Attacker injects extra evidence after approval
    op.add_evidence({"source": "evil_tool", "raw_data": "injected malicious result"})

    result = engine.authorize(
        capability=Capability.WRITE,
        operation=op,
        target_path=tmp_path / "app.py",
    )
    assert result.decision == PolicyDecision.DENY
    assert "EVIDENCE_HASH_MISMATCH" in result.reason


# ── R24: Verification Omission ────────────────────────────────────────────────

def test_r24_verification_omission(tmp_path):
    """
    R24 — ATTACK: Manually set verification={'passed': True} without running gate.
    EXPECTED: DENY — security_scan stage is NOT_RUN.
    """
    ws = tmp_path
    tool = GitCommitTool(workspace_root=ws)
    scope = ExecutionScope(
        workspace_root=str(ws),
        allowed_paths=["app.py"],
        allowed_actions=["WRITE", "COMMIT"],
    )
    scope.lock()
    op = Operation(scope=scope)
    from agos.core.state_machine import OperationState
    for s in [OperationState.EVIDENCE, OperationState.PLAN, OperationState.AWAITING_APPROVAL, OperationState.APPROVED, OperationState.EXECUTING]:
        op.transition_to(s)

    # Attacker manually injects "passed" without running the gate
    op.verification = {"passed": True, "stage_security_scan": "NOT_RUN"}

    result = tool.execute(files=["app.py"], message="bypassing verification", operation=op)
    assert "[COMMIT DENIED]" in result
    assert "security_scan" in result.lower() or "INV-018" in result


# ── R25: Security Scanner Omission ───────────────────────────────────────────

def test_r25_security_scanner_omission(tmp_path):
    """
    R25 — ATTACK: Commit when security scan stage was SKIPPED.
    EXPECTED: DENY — SKIPPED != PASSED.
    """
    ws = tmp_path
    tool = GitCommitTool(workspace_root=ws)
    scope = ExecutionScope(
        workspace_root=str(ws),
        allowed_paths=["app.py"],
        allowed_actions=["WRITE", "COMMIT"],
    )
    scope.lock()
    op = Operation(scope=scope)
    # Verification where scan was skipped
    op.verification = {
        "passed": True,
        "stage_security_scan": StageStatus.SKIPPED.value,
        "operation_id": op.operation_id,
    }

    result = tool.execute(files=["app.py"], message="scan skipped bypass", operation=op)
    assert "[COMMIT DENIED]" in result
    assert "INV-018" in result or "SKIPPED" in result


# ── R26: Verification Replay ──────────────────────────────────────────────────

def test_r26_verification_replay(tmp_path):
    """
    R26 — ATTACK: Reuse verification from a different operation on a new one.
    EXPECTED: DENY — operation_id mismatch.
    """
    ws = tmp_path
    tool = GitCommitTool(workspace_root=ws)
    scope = ExecutionScope(
        workspace_root=str(ws),
        allowed_paths=["app.py"],
        allowed_actions=["WRITE", "COMMIT"],
    )
    scope.lock()
    op = Operation(scope=scope)
    # Verification bound to a different operation
    op.verification = {
        "passed": True,
        "stage_security_scan": StageStatus.PASSED.value,
        "operation_id": "OP-DIFFERENT-0001",  # wrong operation_id
    }

    result = tool.execute(files=["app.py"], message="stale verification", operation=op)
    assert "[COMMIT DENIED]" in result
    assert "Stale" in result or "operation_id" in result or "UNVERIFIED" in result


# ── R27: Stale Verification ───────────────────────────────────────────────────

def test_r27_stale_verification_no_operation_id(tmp_path):
    """
    R27 — ATTACK: verification dict has no operation_id at all.
    EXPECTED: GitCommitTool re-runs verification, which fails (file doesn't exist).
    """
    ws = tmp_path
    tool = GitCommitTool(workspace_root=ws)
    scope = ExecutionScope(
        workspace_root=str(ws),
        allowed_paths=["app.py"],
        allowed_actions=["WRITE", "COMMIT"],
    )
    scope.lock()
    op = Operation(scope=scope)
    # Stale dict without operation_id binding — security scan NOT_RUN
    op.verification = {
        "passed": True,
        "stage_security_scan": "NOT_RUN",
    }

    result = tool.execute(files=["app.py"], message="stale", operation=op)
    # Should be denied because security scan stage is NOT_RUN
    assert "[COMMIT DENIED]" in result


# ── R28: Scope Mutation After Approval ───────────────────────────────────────

def test_r28_scope_mutation_after_approval_locked(tmp_path):
    """
    R28 — ATTACK: Mutate scope.allowed_paths after scope is locked.
    EXPECTED: ScopeLockError raised — mutation physically blocked.
    """
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=["orig.py"])
    scope.lock()

    with pytest.raises((ScopeLockError, AttributeError, TypeError)):
        # All of these should fail on a locked scope
        scope.allowed_paths.append("evil.py")  # type: ignore[union-attr]


def test_r28b_scope_setattr_blocked(tmp_path):
    """
    R28b — ATTACK: Directly reassign scope field after locking.
    EXPECTED: ScopeLockError.
    """
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=["orig.py"])
    scope.lock()

    with pytest.raises(ScopeLockError):
        scope.allowed_paths = ["evil.py"]  # type: ignore[misc]


# ── R29: Concurrent Approval Replay ──────────────────────────────────────────

def test_r29_concurrent_approval_replay(tmp_path):
    """
    R29 — ATTACK: Two threads try to consume the same approval simultaneously.
    EXPECTED: Exactly one succeeds, the other is denied.
    CRIT-01 fix verification.
    """
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=["app.py"])
    gate = ApprovalGate(default_ttl_seconds=60.0)
    app = gate.create_request("OP-CONCURRENT", "dev", "app.py", scope, ["WRITE"])
    gate.grant(app.approval_id, "dev")

    results = []
    scope_hash = scope.compute_hash()

    def try_consume():
        valid, reason = gate.verify_and_consume(
            approval_id=app.approval_id,
            operation_id="OP-CONCURRENT",
            current_scope_hash=scope_hash,
        )
        results.append((valid, reason))

    threads = [threading.Thread(target=try_consume) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r[0] is True]
    failures = [r for r in results if r[0] is False]

    assert len(successes) == 1, f"Exactly 1 success expected, got {len(successes)}"
    assert len(failures) == 9, f"Exactly 9 failures expected, got {len(failures)}"
    for _, reason in failures:
        assert "consumed" in reason.lower() or "APPROVAL" in reason


# ── R30: Audit Tampering ──────────────────────────────────────────────────────

def test_r30_audit_tamper_modified_event(tmp_path):
    """
    R30 — ATTACK: Modify audit event after recording.
    EXPECTED: verify_integrity() returns False [AUDIT_TAMPERING].
    """
    trail = AuditTrail()
    trail.record(
        operation_id="OP-001",
        state="EXECUTING",
        action="WRITE",
        target="app.py",
        result="ALLOW",
        reason="Test event",
    )
    trail.record(
        operation_id="OP-001",
        state="EXECUTING",
        action="COMMIT",
        target="app.py",
        result="ALLOW",
        reason="Test commit",
    )

    # Tamper: change result of first event
    trail._events[0].result = "DENY"  # type: ignore[index]

    ok, reason = trail.verify_integrity()
    assert ok is False
    assert "AUDIT_TAMPERING" in reason


def test_r30b_audit_chain_valid_when_untampered():
    """
    R30b — Verify that an untampered audit chain passes integrity check.
    """
    trail = AuditTrail()
    for i in range(5):
        trail.record(
            operation_id=f"OP-{i:03d}",
            state="EXECUTING",
            action="WRITE",
            target=f"file{i}.py",
            result="ALLOW",
        )
    ok, reason = trail.verify_integrity()
    assert ok is True
    assert reason == "Audit chain integrity verified."


# ── R31: Hardcoded Secret Detection ──────────────────────────────────────────

def test_r31_hardcoded_secret_no_longer_in_provenance(tmp_path):
    """
    R31 — VERIFY: provenance.py no longer contains the hardcoded secret.
    """
    provenance_file = Path(__file__).parent.parent / "agos" / "core" / "provenance.py"
    content = provenance_file.read_text(encoding="utf-8")
    assert "super-tajny-klucz" not in content, (
        "FAIL: Hardcoded secret 'super-tajny-klucz' still present in provenance.py"
    )
    assert "_SYSTEM_SECRET = b\"" not in content, (
        "FAIL: Hardcoded _SYSTEM_SECRET literal still present in provenance.py"
    )


def test_r31b_security_scanner_detects_hardcoded_secret(tmp_path):
    """
    R31b — VERIFY: SecurityScannerTool detects the old hardcoded HMAC key pattern.
    """
    # Create a file with the previously hardcoded secret pattern
    bad_file = tmp_path / "bad_module.py"
    bad_file.write_text(
        '_SYSTEM_SECRET = b"super-tajny-klucz-antigravity-3.1"\n',
        encoding="utf-8",
    )

    from agos.tools.security import SecurityScannerTool
    scanner = SecurityScannerTool(workspace_root=tmp_path)
    result = scanner.execute(filepath="bad_module.py")
    assert "ZNALEZIONO" in result or "Hardcoded" in result or "secret" in result.lower()


# ── R32: Sensitive File Bypass ────────────────────────────────────────────────

def test_r32_sensitive_file_patterns_extended():
    """
    R32 — VERIFY: Extended sensitive file patterns cover required categories.
    """
    # Original patterns
    assert is_sensitive_path(".env") is True
    assert is_sensitive_path(".env.production") is True
    assert is_sensitive_path("certs/server.key") is True
    assert is_sensitive_path("certs/ca.pem") is True
    assert is_sensitive_path("id_rsa") is True
    assert is_sensitive_path(".git/config") is True
    assert is_sensitive_path("credentials.json") is True

    # NEW patterns (LOW-01)
    assert is_sensitive_path("cert.p12") is True
    assert is_sensitive_path("keystore.pfx") is True
    assert is_sensitive_path(".npmrc") is True
    assert is_sensitive_path(".netrc") is True
    assert is_sensitive_path(".dockercfg") is True
    assert is_sensitive_path("service-account.json") is True
    assert is_sensitive_path("kubeconfig") is True
    assert is_sensitive_path(".ssh/id_rsa") is True

    # Safe files should NOT be flagged
    assert is_sensitive_path("src/app.py") is False
    assert is_sensitive_path("README.md") is False


# ── R33: Junction/Reparse Bypass ─────────────────────────────────────────────

def test_r33_junction_bypass_not_testable():
    """
    R33 — NOT_TESTABLE on Windows without elevated privileges.
    Windows junction creation (mklink /J) requires admin rights.
    The resolve_and_validate_path() function handles this via Path.resolve()
    which follows junctions — boundary check catches escaped paths.
    Status: NOT_TESTABLE (platform limitation, not a security gap).
    """
    pytest.skip(
        "NOT_TESTABLE: Windows junction/reparse creation requires elevated privileges. "
        "Path boundary check covers this via Path.resolve() which follows junctions."
    )


# ── R34: Direct Tool Mutation Bypass ─────────────────────────────────────────

def test_r34_direct_tool_mutation_via_registry_denied(tmp_path):
    """
    R34 — ATTACK: Call mutating tool via registry without operation context.
    EXPECTED: DENY [DIRECT_TOOL_BYPASS] — MED-02 architectural guard.
    """
    registry = ToolRegistry()
    modifier = FileModifierTool(workspace_root=tmp_path)
    registry.register(modifier)

    result = registry.execute_tool(
        "file_modifier",
        operation=None,  # no operation context
        filepath="app.py",
        content="malicious content",
    )
    assert "DENY" in str(result.get("decision", "")) or "error" in result
    assert "DIRECT_TOOL_BYPASS" in str(result) or "INV-023" in str(result) or "error" in str(result)


def test_r34b_direct_file_modifier_without_operation_denied(tmp_path):
    """
    R34b — ATTACK: Call FileModifierTool.execute() directly without operation.
    EXPECTED: DENY at PolicyEngine level.
    """
    tool = FileModifierTool(workspace_root=tmp_path)
    result = tool.execute(filepath="app.py", content="evil content", operation=None)
    assert "[POLICY DENIED]" in result


# ── R35: Policy Exception Fail-Open ──────────────────────────────────────────

def test_r35_policy_exception_fails_closed():
    """
    R35 — ATTACK: Trigger exception in PolicyEngine.
    EXPECTED: DENY — fail-closed, never fail-open.
    """
    engine = PolicyEngine()
    result = engine.authorize(capability=None, operation=None)
    assert result.decision == PolicyDecision.DENY
    assert "FAIL CLOSED" in result.reason


def test_r35b_invalid_capability_type_fails_closed():
    """
    R35b — ATTACK: Pass unexpected object type as capability.
    EXPECTED: DENY — fail-closed.
    """
    engine = PolicyEngine()
    result = engine.authorize(capability=object(), operation=None)
    assert result.decision == PolicyDecision.DENY
    assert "FAIL CLOSED" in result.reason


# ── R36: Commit After Failed Security Scan ───────────────────────────────────

def test_r36_commit_after_failed_security_scan(tmp_path):
    """
    R36 — ATTACK: Commit when security scan found vulnerabilities.
    EXPECTED: DENY — stage_security_scan = FAILED blocks commit.
    """
    ws = tmp_path
    bad_file = ws / "app.py"
    bad_file.write_text('api_key = "my-secret-key-12345"\n', encoding="utf-8")

    tool = GitCommitTool(workspace_root=ws)
    scope = ExecutionScope(
        workspace_root=str(ws),
        allowed_paths=["app.py"],
        allowed_actions=["WRITE", "COMMIT"],
    )
    scope.lock()
    op = Operation(scope=scope)

    # Run actual verification — scanner will find the API key
    v_gate = VerificationGate()
    v_result = v_gate.verify(op, files_to_verify=["app.py"])

    # Verification must fail due to security scan
    assert v_result.stage_security_scan == StageStatus.FAILED
    assert v_result.passed is False

    # Commit should be denied
    result = tool.execute(files=["app.py"], message="commit with secrets", operation=op)
    assert "[COMMIT DENIED]" in result


# ── R37: Commit After Skipped Tests ──────────────────────────────────────────

def test_r37_commit_skipped_security_scan_denied(tmp_path):
    """
    R37 — ATTACK: Set security scan to SKIPPED and attempt commit.
    EXPECTED: DENY — SKIPPED != PASSED.
    """
    ws = tmp_path
    tool = GitCommitTool(workspace_root=ws)
    scope = ExecutionScope(
        workspace_root=str(ws),
        allowed_paths=["app.py"],
        allowed_actions=["WRITE", "COMMIT"],
    )
    scope.lock()
    op = Operation(scope=scope)
    op.verification = {
        "passed": True,
        "stage_security_scan": StageStatus.SKIPPED.value,
        "operation_id": op.operation_id,
    }
    result = tool.execute(files=["app.py"], message="skipped scan commit", operation=op)
    assert "[COMMIT DENIED]" in result
    assert "INV-018" in result or "SKIPPED" in result


# ── R38: Commit After Stale Verification ─────────────────────────────────────

def test_r38_stale_verification_different_op_id(tmp_path):
    """
    R38 — ATTACK: Reuse verification from another operation.
    EXPECTED: DENY [UNVERIFIED_SECURITY_STATE].
    """
    ws = tmp_path
    tool = GitCommitTool(workspace_root=ws)
    scope = ExecutionScope(
        workspace_root=str(ws),
        allowed_paths=["app.py"],
        allowed_actions=["WRITE", "COMMIT"],
    )
    scope.lock()
    op = Operation(scope=scope)
    op.verification = {
        "passed": True,
        "stage_security_scan": StageStatus.PASSED.value,
        "operation_id": "OP-DIFFERENT-STALE",
    }
    result = tool.execute(files=["app.py"], message="stale op id", operation=op)
    assert "[COMMIT DENIED]" in result
    assert "Stale" in result or "UNVERIFIED" in result


# ── R39: Approval Target Normalization Attack ─────────────────────────────────

def test_r39_target_normalization_attack(tmp_path):
    """
    R39 — ATTACK: Approval for a.py, request b.py (both in scope).
    EXPECTED: DENY [TARGET_MISMATCH / APPROVAL_TARGET_MISMATCH].
    HIGH-01 fix verification.
    """
    engine = PolicyEngine()
    scope = ExecutionScope(
        workspace_root=str(tmp_path),
        allowed_paths=["a.py", "b.py"],
        allowed_actions=["WRITE"],
    )
    scope.lock()
    op = Operation(scope=scope, target="a.py")

    gate = ApprovalGate()
    app = gate.create_request(op.operation_id, "dev", "a.py", scope, ["WRITE"])
    gate.grant(app.approval_id, "dev")
    gate.verify_and_consume(app.approval_id, op.operation_id, scope.compute_hash(), target="a.py")
    op.approval = app

    op.transition_to(OperationState.EVIDENCE)
    op.transition_to(OperationState.PLAN)
    op.transition_to(OperationState.AWAITING_APPROVAL)
    op.transition_to(OperationState.APPROVED)
    op.transition_to(OperationState.EXECUTING)

    # Attack: request write to b.py (in scope but not approved target)
    result = engine.authorize(
        capability=Capability.WRITE,
        operation=op,
        target_path=tmp_path / "b.py",
    )
    assert result.decision == PolicyDecision.DENY
    assert "TARGET_MISMATCH" in result.reason or "APPROVAL_TARGET_MISMATCH" in result.reason


def test_r39b_exact_approved_target_passes(tmp_path):
    """
    R39b — VERIFY: Approval for a.py, request a.py → ALLOW.
    HIGH-01 fix — correct case should still work.
    """
    (tmp_path / "a.py").write_text("x = 1", encoding="utf-8")
    engine = PolicyEngine()
    scope = ExecutionScope(
        workspace_root=str(tmp_path),
        allowed_paths=["a.py"],
        allowed_actions=["WRITE"],
    )
    scope.lock()
    op = Operation(scope=scope, target="a.py")

    gate = ApprovalGate()
    app = gate.create_request(op.operation_id, "dev", "a.py", scope, ["WRITE"])
    gate.grant(app.approval_id, "dev")
    gate.verify_and_consume(app.approval_id, op.operation_id, scope.compute_hash(), target="a.py")
    op.approval = app

    op.transition_to(OperationState.EVIDENCE)
    op.transition_to(OperationState.PLAN)
    op.transition_to(OperationState.AWAITING_APPROVAL)
    op.transition_to(OperationState.APPROVED)
    op.transition_to(OperationState.EXECUTING)

    result = engine.authorize(
        capability=Capability.WRITE,
        operation=op,
        target_path=tmp_path / "a.py",
    )
    assert result.decision == PolicyDecision.ALLOW


# ── R40: Operation ID Substitution ───────────────────────────────────────────

def test_r40_operation_id_substitution(tmp_path):
    """
    R40 — ATTACK: Create approval for OP-X, try consuming with OP-Y.
    EXPECTED: DENY [APPROVAL_OPERATION_MISMATCH].
    """
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=["a.py"])
    gate = ApprovalGate()

    # Create and grant approval for OP-X
    app_x = gate.create_request("OP-X", "dev", "a.py", scope, ["WRITE"])
    gate.grant(app_x.approval_id, "dev")

    # Create a second operation OP-Y
    # Try to use OP-X's approval for OP-Y
    valid, reason = gate.verify_and_consume(
        approval_id=app_x.approval_id,
        operation_id="OP-Y",  # substituted operation ID
        current_scope_hash=scope.compute_hash(),
    )
    assert valid is False
    assert "APPROVAL_OPERATION_MISMATCH" in reason
    # Ensure OP-X approval is NOT consumed (was rejected before consuming)
    assert app_x.status == ApprovalStatus.GRANTED  # still GRANTED, not CONSUMED

def test_stale_verification_scope_mismatch(tmp_path, monkeypatch):
    """INV-033: Stale verification with different scope_hash must be denied."""
    monkeypatch.setenv("AGOS_PROVENANCE_SECRET", "test-provenance-secret-for-pytest-minimum-32-chars!")
    from agos.tools.git import GitCommitTool
    from agos.core.scope import ExecutionScope
    from agos.core.operation import Operation
    tool = GitCommitTool(workspace_root=tmp_path)
    scope = ExecutionScope(
        workspace_root=str(tmp_path),
        allowed_paths=['app.py'],
        allowed_actions=['WRITE', 'COMMIT']
    )
    op = Operation(scope=scope)
    from agos.core.state_machine import OperationState
    for s in [OperationState.EVIDENCE, OperationState.PLAN, OperationState.AWAITING_APPROVAL, OperationState.APPROVED, OperationState.EXECUTING]:
        op.transition_to(s)

    # Set a verification result with a DIFFERENT scope_hash
    op.verification = {
        'passed': True,
        'operation_id': op.operation_id,
        'scope_hash': 'completely-different-scope-hash-00000000',
        'plan_hash': '',
        'evidence_hash': '',
        'stage_security_scan': 'PASSED',
        'stage_syntax': 'PASSED',
        'stage_scope': 'PASSED',
        'stage_sensitive': 'PASSED',
        'stage_git_diff': 'PASSED',
    }
    res = tool.execute(files=['app.py'], message='test', operation=op)
    assert '[COMMIT DENIED]' in res
    assert 'scope_hash' in res.lower() or 'STALE_VERIFICATION' in res
