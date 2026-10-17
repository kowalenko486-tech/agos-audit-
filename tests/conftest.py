"""
AGOS 3.1 pytest conftest — global test fixtures.
Sets AGOS_PROVENANCE_SECRET for all tests since provenance.py
requires it from the environment (MED-01 fix — no hardcoded secret).
"""
import pytest

PROVENANCE_SECRET = "test-provenance-secret-for-pytest-minimum-32-chars!"


@pytest.fixture(autouse=True, scope="session")
def set_agos_provenance_secret_global(tmp_path_factory):
    """
    Session-scoped: sets AGOS_PROVENANCE_SECRET for the entire test run.
    Module-level autouse fixtures override this if they need a different value.
    """
    import os
    os.environ.setdefault("AGOS_PROVENANCE_SECRET", PROVENANCE_SECRET)
    yield
    # Do not unset — tests that test for missing secret use monkeypatch
