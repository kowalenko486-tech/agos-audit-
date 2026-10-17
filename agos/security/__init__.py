"""AGOS 3.1 Security Package - Hard Boundary, Path Validation, and Capabilities."""
from agos.security.capabilities import Capability
from agos.security.sensitive_files import is_sensitive_path, is_git_internal_path, SENSITIVE_PATTERNS
from agos.security.paths import resolve_and_validate_path, SecurityPathError
from agos.security.workspace import WorkspaceBoundary

__all__ = [
    "Capability",
    "is_sensitive_path",
    "is_git_internal_path",
    "SENSITIVE_PATTERNS",
    "resolve_and_validate_path",
    "SecurityPathError",
    "WorkspaceBoundary",
]
