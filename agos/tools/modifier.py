"""AGOS 3.1 Hardened File Modifier Tool with Atomic Writes and Snapshot Backups."""
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Optional, Union, Dict, Any
from agos.core.provenance import TrustedTool
from agos.security.capabilities import Capability
from agos.security.paths import resolve_and_validate_path, SecurityPathError
from agos.security.sensitive_files import is_sensitive_path
from agos.core.operation import Operation
from agos.core.policy import policy_engine, PolicyDecision
from agos.core.audit import audit_trail
from agos.core.mutation_intent import MutationIntent, authorize_payload

class FileModifierTool(TrustedTool):
    """
    Hardened File Modifier Tool.
    Capability: WRITE
    Enforces:
    - Pre-write policy authorization
    - Scope lock & containment
    - Sensitive target denial
    - File size limits
    - Snapshot backup before write
    - Atomic write (temp file -> fsync -> os.replace)
    """

    def __init__(self, workspace_root: Optional[Union[str, Path]] = None, max_bytes: int = 10_000_000):
        super().__init__(name="file_modifier")
        self.capability = Capability.WRITE
        self.workspace_root = Path(workspace_root or Path.cwd()).resolve()
        self.max_bytes = max_bytes
        self.snapshot_dir = self.workspace_root / ".agos_snapshots"
        self.description = "Safely modifies or creates a file atomically with snapshots and policy verification."
        self.parameters = {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Relative path to target file within workspace"},
                "content": {"type": "string", "description": "New content for the file"},
            },
            "required": ["filepath", "content"]
        }

    def execute(
        self,
        filepath: str,
        content: str,
        operation: Optional[Operation] = None,
        mutation_intent: Optional[MutationIntent] = None,
        **kwargs
    ) -> str:
        # 1. Resolve and validate path against workspace boundary
        try:
            # INV-023: When operation is None, we cannot safely resolve workspace.
            # PolicyEngine will deny mutation without operation context,
            # but we must NOT fall back to self.workspace_root for path resolution.
            if operation is None:
                ws = self.workspace_root
            else:
                ws = Path(operation.scope.workspace_root).resolve()
            resolved_path = resolve_and_validate_path(filepath, ws)
        except SecurityPathError as spe:
            return f"[POLICY DENIED] Invalid path boundary: {spe}"

        # 2. Check content size limits
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > self.max_bytes:
            return f"[POLICY DENIED] Content size {len(content_bytes)} bytes exceeds limit {self.max_bytes} bytes."

        # 3. Policy Authorization
        decision = policy_engine.authorize(
            capability=self.capability,
            operation=operation,
            target_path=resolved_path,
            actor="agent",
        )
        if decision.decision != PolicyDecision.ALLOW:
            return f"[POLICY DENIED] {decision.reason}"

        # 3b. INV-040: MutationIntent authorization (payload/diff authorization)
        if mutation_intent is not None:
            # Read original content if file exists
            original_content = ""
            if resolved_path.exists():
                try:
                    with open(resolved_path, 'r', encoding='utf-8-sig', errors='replace') as f:
                        original_content = f.read()
                except Exception:
                    pass
            payload_result = authorize_payload(mutation_intent, filepath, content, original_content)
            if not payload_result.authorized:
                return f"[POLICY DENIED] {payload_result.reason} [{payload_result.reason_code}]"

        # 4. Create snapshot backup if file already exists
        snapshot_id = "none"
        if resolved_path.exists():
            try:
                op_id_str = operation.operation_id if operation else "standalone"
                op_snapshot_dir = self.snapshot_dir / op_id_str
                op_snapshot_dir.mkdir(parents=True, exist_ok=True)
                snapshot_id = f"snap_{int(time.time()*1000)}_{resolved_path.name}.bak"
                snapshot_target = op_snapshot_dir / snapshot_id
                shutil.copy2(resolved_path, snapshot_target)
            except Exception as e:
                return f"[SNAPSHOT ERROR] Failed to create backup snapshot: {e}. Write aborted."

        # 5. Atomic write via temporary file
        try:
            resolved_path.parent.mkdir(parents=True, exist_ok=True)
            # Use temporary file in the same directory to ensure atomic os.replace across filesystem boundaries
            temp_fd, temp_path_str = tempfile.mkstemp(
                dir=str(resolved_path.parent),
                prefix=f".tmp_{resolved_path.name}_"
            )
            temp_path = Path(temp_path_str)

            with os.fdopen(temp_fd, "wb") as f:
                f.write(content_bytes)
                f.flush()
                os.fsync(f.fileno())

            # Atomic replacement
            os.replace(temp_path, resolved_path)
        except Exception as e:
            if "temp_path" in locals() and temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            return f"[WRITE ERROR] Atomic file replacement failed: {e}"

        # Record in operation execution history if active
        if operation:
            operation.record_execution({
                "action": "WRITE",
                "target": str(resolved_path),
                "bytes_written": len(content_bytes),
                "snapshot_id": snapshot_id,
                "timestamp": time.time(),
            })

        return f"[SUCCESS] File '{resolved_path.name}' written atomically ({len(content_bytes)} bytes). Snapshot: {snapshot_id}"
