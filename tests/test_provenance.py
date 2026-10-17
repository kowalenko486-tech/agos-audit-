"""Tests for AGOS 3.1 Provenance — requires AGOS_PROVENANCE_SECRET env var."""
import os
import pytest
from pydantic import ValidationError
from agos.core.models import Evidence, VerifiedStatement
from agos.core.provenance import TrustedTool, generate_provenance_hash, verify_provenance_hash


# All tests in this module require the secret env var to be set
PROVENANCE_SECRET = "test-provenance-secret-for-pytest-minimum-32-chars!"


@pytest.fixture(autouse=True)
def set_provenance_secret(monkeypatch):
    """Set AGOS_PROVENANCE_SECRET for every test in this module."""
    monkeypatch.setenv("AGOS_PROVENANCE_SECRET", PROVENANCE_SECRET)


class MockDatabaseTool(TrustedTool):
    def __init__(self):
        super().__init__(name="db_query")

    def execute(self, query: str) -> str:
        return "Znaleziono 5 rekordów dla zapytania: " + query


def test_forged_evidence_rejected():
    """Agent simulates forged evidence with wrong hash — must be rejected."""
    with pytest.raises(ValidationError) as exc_info:
        Evidence(
            source="db_query",
            raw_data="Zmyślone wyniki z bazy danych",
            provenance_hash="bad_hash_12345",
        )
    assert "Fałszerstwo dowodu" in str(exc_info.value)


def test_trusted_tool_evidence_accepted():
    """Trusted tool generates valid evidence — must be accepted."""
    tool = MockDatabaseTool()
    tool_result = tool.run_and_sign(query="SELECT * FROM users")

    statement = VerifiedStatement(
        claim="Mamy 5 użytkowników w bazie danych.",
        evidences=[Evidence(**tool_result)],
    )

    assert statement.claim == "Mamy 5 użytkowników w bazie danych."
    assert len(statement.evidences) == 1
    assert statement.evidences[0].provenance_hash == tool_result["provenance_hash"]


def test_provenance_secret_missing_fails_closed(monkeypatch):
    """MED-01 / R31: System must fail closed if AGOS_PROVENANCE_SECRET is not set."""
    monkeypatch.delenv("AGOS_PROVENANCE_SECRET", raising=False)
    with pytest.raises(RuntimeError) as exc_info:
        generate_provenance_hash("any_source", "any_data")
    assert "AGOS_PROVENANCE_SECRET" in str(exc_info.value)
    assert "FAIL CLOSED" in str(exc_info.value)


def test_provenance_secret_too_short_fails_closed(monkeypatch):
    """MED-01: Secret too short must fail closed."""
    monkeypatch.setenv("AGOS_PROVENANCE_SECRET", "short")
    with pytest.raises(RuntimeError) as exc_info:
        generate_provenance_hash("any_source", "any_data")
    assert "too short" in str(exc_info.value)


def test_provenance_hash_verify_correct():
    """Correct hash verifies correctly."""
    h = generate_provenance_hash("tool", "data")
    assert verify_provenance_hash("tool", "data", h) is True


def test_provenance_hash_verify_wrong():
    """Wrong hash is rejected."""
    assert verify_provenance_hash("tool", "data", "wrong_hash") is False

def test_validate_provenance_secret_at_startup_passes(monkeypatch):
    monkeypatch.setenv('AGOS_PROVENANCE_SECRET', 'test-secret-minimum-32-characters-long!!')
    from agos.core.provenance import validate_provenance_secret_at_startup
    assert validate_provenance_secret_at_startup() is True

def test_validate_provenance_secret_at_startup_missing_raises(monkeypatch):
    monkeypatch.delenv('AGOS_PROVENANCE_SECRET', raising=False)
    from agos.core.provenance import validate_provenance_secret_at_startup
    import importlib, agos.core.provenance
    importlib.reload(agos.core.provenance)
    from agos.core.provenance import validate_provenance_secret_at_startup
    with pytest.raises(RuntimeError, match='must be set'):
        validate_provenance_secret_at_startup()

def test_audit_trail_persistence(tmp_path):
    from agos.core.audit import AuditTrail
    audit_file = str(tmp_path / 'audit.jsonl')
    trail = AuditTrail(audit_file=audit_file)
    trail.record('OP-1', 'EXECUTING', 'WRITE', 'app.py', 'ALLOW', 'test event')
    trail.record('OP-1', 'EXECUTING', 'WRITE', 'app.py', 'ALLOW', 'second event')
    # Load from file
    import os
    assert os.path.exists(audit_file)
    with open(audit_file, 'r') as f:
        lines = [l.strip() for l in f if l.strip()]
    assert len(lines) == 2

def test_audit_trail_load_from_file(tmp_path):
    from agos.core.audit import AuditTrail
    audit_file = str(tmp_path / 'audit.jsonl')
    trail = AuditTrail(audit_file=audit_file)
    trail.record('OP-1', 'EXECUTING', 'WRITE', 'app.py', 'ALLOW', 'event 1')
    trail.record('OP-2', 'STOP', 'COMMIT', 'app.py', 'ALLOW', 'event 2')
    # Load from file into a new trail
    trail2 = AuditTrail.load_from_file(audit_file)
    assert len(trail2.get_events()) == 2

