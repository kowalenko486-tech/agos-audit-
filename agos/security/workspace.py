"""AGOS 3.1 Workspace Boundary Manager."""
import os
from pathlib import Path
from typing import Union, Optional
from agos.security.paths import resolve_and_validate_path, SecurityPathError
from agos.security.sensitive_files import is_sensitive_path

class WorkspaceBoundary:
    """Encapsulates the canonical workspace boundary for an AGOS session or operation."""

    def __init__(self, workspace_root: Optional[Union[str, Path]] = None):
        if workspace_root is None:
            # Default to current working directory
            self.root = Path.cwd().resolve()
        else:
            self.root = Path(workspace_root).resolve()

        if not self.root.exists() or not self.root.is_dir():
            raise SecurityPathError(f"Workspace root does not exist or is not a directory: {self.root}")

    def resolve(self, path: Union[str, Path], allow_symlinks: bool = False, must_exist: bool = False) -> Path:
        """Resolves and validates that the path is within the workspace boundary."""
        return resolve_and_validate_path(
            path=path,
            workspace_root=self.root,
            allow_symlinks=allow_symlinks,
            must_exist=must_exist
        )

    def is_inside(self, path: Union[str, Path]) -> bool:
        """Returns True if path resolves strictly within the workspace."""
        try:
            self.resolve(path)
            return True
        except SecurityPathError:
            return False

    def is_sensitive(self, path: Union[str, Path]) -> bool:
        """Checks if the path refers to a sensitive file or directory."""
        return is_sensitive_path(path)

    def __str__(self) -> str:
        return str(self.root)
