"""AGOS 3.2 Concurrency + Race Condition Tests.
Verifies that security controls hold under concurrent access.
"""
import threading
import time
import pytest
from pathlib import Path

from agos.core.scope import ExecutionScope
from agos.core.approval import ApprovalGate, ApprovalStatus
from agos.core.audit import AuditTrail


def test_concurrent_approval_consume_exactly_one_wins(tmp_path):
    """Under concurrent load, exactly ONE verify_and_consume() call succeeds."""
    gate = ApprovalGate()
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=['app.py'])
    app = gate.create_request('OP-1', 'dev', 'app.py', scope, ['WRITE'])
    gate.grant(app.approval_id, 'dev')
    
    results = []
    barrier = threading.Barrier(20)
    
    def race_consume():
        barrier.wait()  # All start simultaneously
        ok, _ = gate.verify_and_consume(app.approval_id, 'OP-1', scope.compute_hash())
        results.append(ok)
    
    threads = [threading.Thread(target=race_consume) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=10)
    
    assert len(results) == 20
    assert results.count(True) == 1, f'Expected exactly 1 success, got {results.count(True)}'
    assert results.count(False) == 19


def test_concurrent_audit_record_no_chain_corruption(tmp_path):
    """Concurrent audit record operations do not corrupt the hash chain."""
    trail = AuditTrail()
    errors = []
    
    def record_event(i):
        try:
            trail.record(f'OP-{i}', 'EXECUTING', 'WRITE', f'file_{i}.py', 'ALLOW', f'Event {i}')
        except Exception as e:
            errors.append(e)
    
    threads = [threading.Thread(target=record_event, args=(i,)) for i in range(50)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=10)
    
    assert not errors, f'Concurrent audit errors: {errors}'
    assert len(trail.get_events()) == 50
    # Verify chain integrity after concurrent writes
    is_valid, _ = trail.verify_integrity()
    assert is_valid is True


def test_concurrent_scope_lock_immutable(tmp_path):
    """Locked scope remains immutable under concurrent access attempts."""
    scope = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=['app.py'])
    scope.lock()
    
    failures = []
    
    def try_mutate():
        try:
            scope.allowed_paths.append('evil.py')  # tuple — AttributeError
            failures.append('MUTATION_SUCCEEDED')
        except (AttributeError, TypeError):
            pass  # Expected
        except Exception as e:
            failures.append(str(e))
    
    threads = [threading.Thread(target=try_mutate) for _ in range(20)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=5)
    
    assert not failures, f'Scope mutations succeeded: {failures}'
    assert list(scope.allowed_paths) == ['app.py']  # Unchanged


def test_concurrent_approval_grant_no_double_grant():
    """Concurrent grant attempts do not corrupt approval state."""
    gate = ApprovalGate()
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        scope = ExecutionScope(workspace_root=tmp, allowed_paths=['app.py'])
        app = gate.create_request('OP-1', 'dev', 'app.py', scope, ['WRITE'])
        
        grant_results = []
        
        def try_grant():
            try:
                gate.grant(app.approval_id, 'dev')
                grant_results.append('GRANTED')
            except Exception as e:
                grant_results.append(f'ERROR: {e}')
        
        threads = [threading.Thread(target=try_grant) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=5)
        
        # All grants should succeed (grant is idempotent for PENDING -> GRANTED)
        # But the approval status should be GRANTED (not double-granted)
        assert app.status in (ApprovalStatus.GRANTED,)


def test_sequential_operations_no_state_leakage(tmp_path):
    """Sequential operations do not leak state between them."""
    from agos.core.operation import Operation
    from agos.core.state_machine import OperationState
    
    # Create operation 1 and transition it
    scope1 = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=['app.py'])
    op1 = Operation(scope=scope1)
    op1.transition_to(OperationState.EVIDENCE)
    op1.set_plan('Plan for op1')
    
    # Create operation 2 — completely independent
    scope2 = ExecutionScope(workspace_root=str(tmp_path), allowed_paths=['other.py'])
    op2 = Operation(scope=scope2)
    
    # op2 state should be independent of op1
    assert op2.state == OperationState.READ_ONLY
    assert not op2.plan  # plan is None or '' by default \u2014 no plan set
    assert op1.operation_id != op2.operation_id

