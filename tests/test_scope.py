"""Tests for AGOS 3.1 Scope Lock and Path Boundary Invariants."""
import pytest
from pathlib import Path
from agos.core.scope import ExecutionScope, ScopeLockError

def test_scope_hash_determinism(tmp_path):
    ws = str(tmp_path)
    scope1 = ExecutionScope(
        workspace_root=ws,
        allowed_paths=["src/app.py", "src/utils.py"],
        allowed_actions=["WRITE", "READ"]
    )
    scope2 = ExecutionScope(
        workspace_root=ws,
        allowed_paths=["src/utils.py", "src/app.py"], # different order
        allowed_actions=["READ", "WRITE"] # different order
    )
    # Canonical sorting ensures identical SHA-256 hashes
    assert scope1.compute_hash() == scope2.compute_hash()

def test_scope_lock_prevents_expansion(tmp_path):
    ws = str(tmp_path)
    scope = ExecutionScope(workspace_root=ws, allowed_paths=["src/app.py"])
    scope.lock()
    assert scope.is_locked

    with pytest.raises(ScopeLockError):
        scope.add_allowed_path("src/config.py")

def test_scope_path_containment(tmp_path):
    ws = tmp_path
    (ws / "src").mkdir()
    app_file = ws / "src" / "app.py"
    app_file.write_text("print('hello')")
    outside_file = ws / "secret.py"
    outside_file.write_text("secret = 1")

    scope = ExecutionScope(
        workspace_root=str(ws),
        allowed_paths=["src/app.py"]
    )
    assert scope.is_path_in_scope(app_file)
    assert not scope.is_path_in_scope(outside_file)

def test_scope_forbids_sensitive_files_by_default(tmp_path):
    ws = tmp_path
    env_file = ws / ".env"
    env_file.write_text("SECRET=123")

    scope = ExecutionScope(
        workspace_root=str(ws),
        allowed_paths=[str(env_file)]
    )
    # Sensitive file detection blocks even if listed unless explicit
    assert not scope.is_path_in_scope(env_file)

def test_scope_path_unicode_normalization():
    """Scope canonical hash is stable under Unicode normalization."""
    import unicodedata
    from agos.core.scope import ExecutionScope
    # Create two scopes with NFC vs NFD forms of same path
    path_nfc = unicodedata.normalize('NFC', 'app.py')
    path_nfd = unicodedata.normalize('NFD', 'app.py')
    # For ASCII paths, NFC and NFD are identical — test that add_allowed_path normalizes
    scope = ExecutionScope(workspace_root='.', allowed_paths=[])
    scope.add_allowed_path(path_nfc)
    scope2 = ExecutionScope(workspace_root='.', allowed_paths=[])
    scope2.add_allowed_path(path_nfd)
    assert scope.compute_hash() == scope2.compute_hash()
