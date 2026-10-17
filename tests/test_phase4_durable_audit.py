"""Tests for Phase 4: Durable Append-Only JSONL Audit Trail, Startup Chain Verification & Concurrency."""
import json
import threading
import pytest

from agos.core.audit import AuditTrail


def test_audit_trail_env_var_auto_binding_and_parent_dir_creation(tmp_path, monkeypatch):
    nested_audit_file = tmp_path / "logs" / "nested" / "agos_audit.jsonl"
    monkeypatch.setenv("AGOS_AUDIT_FILE", str(nested_audit_file))

    trail = AuditTrail()
    assert trail.get_stats()["has_persistence"] is True
    assert trail.get_stats()["audit_file"] == str(nested_audit_file)

    trail.record("OP-100", "READ_ONLY", "READ", "README.md", "ALLOW", reason="Initial read")
    assert nested_audit_file.exists()
    assert trail.count() == 1


def test_multi_session_hash_chain_continuation_and_startup_verification(tmp_path):
    audit_path = str(tmp_path / "chain.jsonl")

    # Session 1: write 3 events
    session1 = AuditTrail(audit_file=audit_path, fsync=True)
    e1 = session1.record("OP-1", "READ_ONLY", "READ", "a.py", "ALLOW", reason="step 1")
    e2 = session1.record("OP-1", "EXECUTING", "WRITE", "a.py", "ALLOW", reason="step 2")
    e3 = session1.record("OP-1", "STOP", "COMMIT", "a.py", "ALLOW", reason="step 3")
    assert e1.prev_event_hash == ""
    assert e2.prev_event_hash == e1.event_hash
    assert e3.prev_event_hash == e2.event_hash

    # Session 2: restart and continue chain on the same file
    session2 = AuditTrail(audit_file=audit_path)
    assert session2.count() == 3
    e4 = session2.record("OP-2", "READ_ONLY", "ANALYZE", "b.py", "ALLOW", reason="step 4")
    e5 = session2.record("OP-2", "STOP", "READ", "b.py", "ALLOW", reason="step 5")
    assert e4.prev_event_hash == e3.event_hash
    assert e5.prev_event_hash == e4.event_hash

    # Session 3: cold reload and verify full 5-event chain
    session3 = AuditTrail.load_from_file(audit_path)
    assert session3.count() == 5
    is_valid, msg = session3.verify_integrity()
    assert is_valid is True
    assert "verified" in msg


def test_startup_fails_closed_on_modified_jsonl_event(tmp_path):
    audit_path = tmp_path / "tampered_mod.jsonl"
    trail = AuditTrail(audit_file=str(audit_path))
    trail.record("OP-1", "EXECUTING", "WRITE", "app.py", "ALLOW", reason="legit write")
    trail.record("OP-1", "STOP", "COMMIT", "app.py", "ALLOW", reason="legit commit")

    # Tamper with the first event's target on disk without updating hashes
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    first_obj = json.loads(lines[0])
    first_obj["target"] = "evil.py"
    lines[0] = json.dumps(first_obj)
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError) as exc_info:
        AuditTrail(audit_file=str(audit_path))
    assert "Audit chain broken" in str(exc_info.value)
    assert "AUDIT_TAMPERING" in str(exc_info.value)


def test_startup_fails_closed_on_deleted_middle_jsonl_event(tmp_path):
    audit_path = tmp_path / "tampered_del.jsonl"
    trail = AuditTrail(audit_file=str(audit_path))
    trail.record("OP-1", "READ_ONLY", "READ", "1.py", "ALLOW")
    trail.record("OP-1", "EXECUTING", "WRITE", "2.py", "ALLOW")
    trail.record("OP-1", "STOP", "COMMIT", "3.py", "ALLOW")

    # Delete the middle event (index 1) from disk
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError) as exc_info:
        AuditTrail(audit_file=str(audit_path))
    assert "Audit chain broken" in str(exc_info.value)
    assert "prev_event_hash mismatch" in str(exc_info.value)


def test_concurrent_persistent_jsonl_writes_integrity(tmp_path):
    """Concurrency gate: 30 threads writing simultaneously to persistent JSONL file."""
    audit_path = str(tmp_path / "concurrent_audit.jsonl")
    trail = AuditTrail(audit_file=audit_path)
    errors = []
    barrier = threading.Barrier(30)

    def worker(idx: int):
        try:
            barrier.wait()
            trail.record(
                operation_id=f"OP-CONC-{idx}",
                state="EXECUTING",
                action="WRITE",
                target=f"module_{idx}.py",
                result="ALLOW",
                reason=f"Concurrent persistent write {idx}",
            )
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors, f"Unexpected errors during concurrent persistent audit writes: {errors}"
    assert trail.count() == 30

    # Reload from disk in a fresh AuditTrail instance and verify chain integrity
    reloaded = AuditTrail.load_from_file(audit_path)
    assert reloaded.count() == 30
    is_valid, _ = reloaded.verify_integrity()
    assert is_valid is True


def test_persistent_audit_redacts_secrets_before_disk_write(tmp_path, monkeypatch):
    monkeypatch.setenv("AGOS_PROVENANCE_SECRET", "top-secret-provenance-key-32-bytes-minimum!!")
    audit_path = tmp_path / "redacted_audit.jsonl"
    trail = AuditTrail(audit_file=str(audit_path))

    trail.record(
        operation_id="OP-SEC",
        state="READ_ONLY",
        action="ANALYZE",
        target="config.py",
        result="DENY",
        reason="Leaked sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456 and top-secret-provenance-key-32-bytes-minimum!!",
        metadata={"aws": "AKIAIOSFODNN7EXAMPLE"},
    )

    raw_disk = audit_path.read_text(encoding="utf-8")
    assert "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456" not in raw_disk
    assert "top-secret-provenance-key-32-bytes-minimum!!" not in raw_disk
    assert "AKIAIOSFODNN7EXAMPLE" not in raw_disk
    assert "[REDACTED_OPENAI_KEY]" in raw_disk
    assert "[REDACTED_SYSTEM_SECRET]" in raw_disk
    assert "[REDACTED_AWS_KEY]" in raw_disk
