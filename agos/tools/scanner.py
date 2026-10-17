"""AGOS 3.1 Hardened Project Scanner Tool."""
import os
import json
from pathlib import Path
from typing import Optional, Union, Dict, Any, List
from agos.core.provenance import TrustedTool
from agos.security.capabilities import Capability
from agos.security.paths import resolve_and_validate_path, SecurityPathError
from agos.security.sensitive_files import is_sensitive_path
from agos.core.operation import Operation
from agos.core.policy import policy_engine, PolicyDecision

class ProjectScannerTool(TrustedTool):
    """
    Hardened Project Scanner Tool.
    Capability: READ
    Enforces:
    - Workspace boundary
    - Symlink escape prevention
    - File and depth limits
    - Sensitive path exclusion
    """

    def __init__(
        self,
        workspace_root: Optional[Union[str, Path]] = None,
        max_files: int = 500,
        max_depth: int = 10
    ):
        super().__init__(name="project_scanner")
        self.capability = Capability.READ
        self._custom_workspace = Path(workspace_root).resolve() if workspace_root else None
        self.max_files = max_files
        self.max_depth = max_depth
        self.description = "Scans project directories within workspace boundary, observing limits and sensitive masks."
        self.parameters = {
            "type": "object",
            "properties": {
                "directory": {"type": "string", "description": "Relative directory path to scan"},
                "max_depth": {"type": "integer", "description": "Maximum depth to recurse"},
            },
            "required": []
        }

    @property
    def workspace_root(self) -> Path:
        if self._custom_workspace:
            return self._custom_workspace
        from agos.core.workspace_manager import workspace_manager
        return workspace_manager.get_current_workspace()

    @workspace_root.setter
    def workspace_root(self, val: Union[str, Path]):
        self._custom_workspace = Path(val).resolve()

    def execute(
        self,
        directory: str = ".",
        max_depth: Optional[int] = None,
        operation: Optional[Operation] = None,
        **kwargs
    ) -> str:
        ws = Path(operation.scope.workspace_root).resolve() if operation else self.workspace_root

        try:
            target_dir = resolve_and_validate_path(directory, ws, allow_symlinks=False, must_exist=True)
        except SecurityPathError as spe:
            return json.dumps({"error": f"[ACCESS DENIED] {spe}"})

        # Policy check
        decision = policy_engine.authorize(
            capability=self.capability,
            operation=operation,
            target_path=target_dir,
            actor="agent",
        )
        if decision.decision != PolicyDecision.ALLOW:
            return json.dumps({"error": f"[POLICY DENIED] {decision.reason}"})

        depth_limit = max_depth if max_depth is not None else self.max_depth
        files_found: List[Dict[str, Any]] = []
        truncated = False

        try:
            for root, dirs, files in os.walk(target_dir):
                root_path = Path(root)
                # Check depth
                rel = root_path.relative_to(target_dir)
                if len(rel.parts) > depth_limit:
                    dirs.clear() # don't recurse deeper
                    continue

                # Filter out sensitive or hidden internal directories from traversal
                dirs[:] = [d for d in dirs if not is_sensitive_path(root_path / d) and d not in (".git", "venv", "__pycache__")]

                for f in files:
                    file_path = root_path / f
                    # Prevent symlink escapes
                    if file_path.is_symlink():
                        continue

                    # Mask sensitive files from details
                    if is_sensitive_path(file_path):
                        files_found.append({
                            "path": str(file_path.relative_to(ws)).replace("\\", "/"),
                            "status": "PROTECTED_SENSITIVE",
                            "size": 0
                        })
                    else:
                        files_found.append({
                            "path": str(file_path.relative_to(ws)).replace("\\", "/"),
                            "size": file_path.stat().st_size
                        })

                    if len(files_found) >= self.max_files:
                        truncated = True
                        break

                if truncated:
                    break

            return json.dumps({
                "base_dir": str(target_dir.relative_to(ws)).replace("\\", "/"),
                "total_scanned": len(files_found),
                "truncated": truncated,
                "entries": files_found
            }, indent=2)

        except Exception as e:
            return json.dumps({"error": f"Scan failed: {str(e)}"})
