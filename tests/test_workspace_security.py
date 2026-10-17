"""Tests for AGOS 3.1 Workspace Boundary, Path Traversal, and Symlink Guards."""
import pytest
from pathlib import Path
from agos.security.paths import resolve_and_validate_path, SecurityPathError
from agos.security.sensitive_files import is_sensitive_path
from agos.security.workspace import WorkspaceBoundary

def test_path_traversal_rejected(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("classified")

    boundary = WorkspaceBoundary(ws)

    with pytest.raises(SecurityPathError) as exc:
        boundary.resolve("../secret.txt")
    assert "escapes workspace" in str(exc.value)

def test_unc_path_rejected(tmp_path):
    boundary = WorkspaceBoundary(tmp_path)
    with pytest.raises(SecurityPathError) as exc:
        boundary.resolve(r"\\192.168.1.1\share\exploit.txt")
    assert "UNC or device namespace" in str(exc.value)

def test_absolute_external_path_rejected(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    boundary = WorkspaceBoundary(ws)

    external_path = tmp_path / "external.txt"
    with pytest.raises(SecurityPathError) as exc:
        boundary.resolve(str(external_path.resolve()))
    assert "escapes workspace" in str(exc.value)

def test_symlink_escape_rejected(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    outside_target = tmp_path / "outside.txt"
    outside_target.write_text("secret outside")

    symlink_file = ws / "link_to_outside.txt"
    try:
        symlink_file.symlink_to(outside_target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation not supported or permitted on this OS/user environment.")

    boundary = WorkspaceBoundary(ws)
    with pytest.raises(SecurityPathError) as exc:
        boundary.resolve("link_to_outside.txt", allow_symlinks=False)
    assert "escapes workspace" in str(exc.value) or "Symlinks are disallowed" in str(exc.value)

def test_sensitive_file_identification():
    assert is_sensitive_path(".env") is True
    assert is_sensitive_path(".env.production") is True
    assert is_sensitive_path("certs/server.key") is True
    assert is_sensitive_path("certs/ca.pem") is True
    assert is_sensitive_path("id_rsa") is True
    assert is_sensitive_path(".git/config") is True
    assert is_sensitive_path(".git/HEAD") is True
    assert is_sensitive_path("credentials.json") is True
    assert is_sensitive_path("src/app.py") is False

def test_unicode_confusable_target_mismatch():
    """PI-004: Unicode confusable path should not bypass target binding."""
    import unicodedata
    from agos.core.approval import ApprovalGate
    from agos.core.scope import ExecutionScope
    gate = ApprovalGate()
    scope = ExecutionScope(workspace_root='.', allowed_paths=['app.py'])
    app = gate.create_request('OP-1', 'dev', 'app.py', scope, ['WRITE'])
    gate.grant(app.approval_id, 'dev')
    cyrillic_app_py = 'аpp.py'  # Cyrillic 'а' (U+0430) + 'pp.py'
    ok, reason = gate.verify_and_consume(app.approval_id, 'OP-1', scope.compute_hash(), target=cyrillic_app_py)
    assert ok is False, f"Should deny Unicode confusable target, got: {reason}"

def test_sensitive_path_unicode_normalized():
    """is_sensitive_path must detect sensitive files with NFC-normalized names."""
    import unicodedata
    from agos.security.sensitive_files import is_sensitive_path
    # .env in NFC form
    assert is_sensitive_path('.env') is True
    assert is_sensitive_path('.ENV') is True
    # id_rsa variations
    assert is_sensitive_path('id_rsa') is True
    assert is_sensitive_path('path/to/id_rsa') is True
    # Non-sensitive
    assert is_sensitive_path('app.py') is False
