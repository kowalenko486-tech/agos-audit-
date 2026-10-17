"""AGOS 3.1 Path Resolution and Security Boundary Validation."""
import os
import sys
import unicodedata
from pathlib import Path
from typing import Union, Optional

class SecurityPathError(ValueError):
    """Raised when a path violates security boundaries."""
    pass

def resolve_and_validate_path(
    path: Union[str, Path],
    workspace_root: Union[str, Path],
    allow_symlinks: bool = False,
    must_exist: bool = False
) -> Path:
    """
    Canonically resolves and strictly validates a path against the authorized workspace root.
    Protects against:
    - Path traversal attacks (..)
    - Absolute external paths (e.g. /etc/passwd or D:\\outside)
    - UNC network paths (\\\\host\\share)
    - Windows device paths (\\\\?\\C:\\)
    - Symlink escapes
    - Non-normalized separator manipulation
    """
    if not path:
        raise SecurityPathError("Path cannot be empty.")

    raw_path_str = unicodedata.normalize('NFC', str(path).strip())

    # Reject UNC paths and Windows device namespaces
    if raw_path_str.startswith(("\\\\", "//", "\\\\?\\", "\\\\.\\")):
        raise SecurityPathError(f"UNC or device namespace paths are strictly forbidden: {raw_path_str}")

    try:
        ws_root = Path(workspace_root).resolve(strict=True)
    except Exception as e:
        raise SecurityPathError(f"Authorized workspace root cannot be resolved: {e}")

    target_path = Path(raw_path_str)

    # If relative, resolve relative to workspace_root
    if not target_path.is_absolute():
        combined_path = ws_root / target_path
    else:
        combined_path = target_path

    # Canonicalize and resolve all parent components
    try:
        # If target exists or must_exist is True
        if combined_path.exists():
            resolved = combined_path.resolve(strict=True)
            if not allow_symlinks and combined_path.is_symlink():
                raise SecurityPathError(f"Symlinks are disallowed for this operation: {combined_path}")

            # Check for Windows junctions and reparse points
            if sys.platform == 'win32':
                try:
                    import ctypes
                    FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
                    attrs = ctypes.windll.kernel32.GetFileAttributesW(str(combined_path))
                    if attrs != -1 and (attrs & FILE_ATTRIBUTE_REPARSE_POINT):
                        if not allow_symlinks:
                            raise SecurityPathError(
                                f"Windows reparse point/junction at '{combined_path}' "
                                f"is disallowed for this operation."
                            )
                except SecurityPathError:
                    raise
                except Exception:
                    pass  # If we can't check, conservative: allow (path boundary check still applies)
        else:
            if must_exist:
                raise SecurityPathError(f"Target path does not exist: {combined_path}")
            # Target does not exist yet (e.g. creating a new file)
            # Resolve parent canonical path and append target name
            parent_resolved = combined_path.parent.resolve(strict=False)
            resolved = (parent_resolved / combined_path.name).resolve(strict=False)
    except SecurityPathError:
        raise
    except Exception as e:
        raise SecurityPathError(f"Failed to securely resolve path {target_path}: {e}")

    # Boundary verification: resolved path MUST be strictly inside workspace_root
    try:
        # relative_to will raise ValueError if resolved is outside ws_root
        resolved.relative_to(ws_root)
    except ValueError:
        raise SecurityPathError(
            f"Access Denied: Path '{raw_path_str}' escapes workspace root '{ws_root}' (Resolved: '{resolved}')"
        )

    # Check symlink escapes on all path components if symlinks are not allowed
    if not allow_symlinks:
        curr = combined_path
        while curr != curr.parent:
            if curr.is_symlink():
                real_target = curr.resolve()
                try:
                    real_target.relative_to(ws_root)
                except ValueError:
                    raise SecurityPathError(f"Symlink component '{curr}' escapes workspace root to '{real_target}'")
            if curr == ws_root:
                break
            curr = curr.parent

    return resolved
