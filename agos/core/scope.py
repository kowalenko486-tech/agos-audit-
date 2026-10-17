"""AGOS 3.1 Scope Model, Immutable Scope Lock, and Canonical Hashing."""
import hashlib
import json
import unicodedata
from pathlib import Path
from typing import List, Optional, Union
from pydantic import BaseModel, Field, ConfigDict, PrivateAttr
from agos.security.paths import resolve_and_validate_path, SecurityPathError
from agos.security.sensitive_files import is_sensitive_path


class ScopeLockError(RuntimeError):
    """Raised when an attempt is made to mutate a locked scope or violate scope rules."""
    pass


class ExecutionScope(BaseModel):
    """
    MED-03 FIX: _locked is now a proper Pydantic PrivateAttr.
    When locked, ALL mutation of scope fields is blocked via __setattr__ override,
    including direct list mutations detected at attribute-set level.
    The allowed_paths and forbidden_paths lists are converted to tuples on lock
    to prevent in-place .append() bypasses.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    workspace_root: str
    allowed_paths: List[str] = Field(default_factory=list)
    allowed_actions: List[str] = Field(default_factory=lambda: ["READ", "ANALYZE"])
    forbidden_paths: List[str] = Field(default_factory=list)
    max_files: int = 100
    max_bytes: int = 10_000_000  # 10 MB
    max_operations: int = 50
    allow_create: bool = True
    allow_modify: bool = True
    allow_delete: bool = False
    allow_rename: bool = False
    allow_git_commit: bool = False
    allow_git_push: bool = False
    allow_sensitive: bool = False

    # MED-03 FIX: PrivateAttr — Pydantic v2 private field, not a model field
    _locked: bool = PrivateAttr(default=False)

    def model_post_init(self, __context) -> None:
        """Ensure _locked starts False after construction."""
        self._locked = False

    def lock(self) -> None:
        """
        Locks the scope making it completely immutable.
        After locking, converts mutable lists to tuples to prevent .append() bypasses.
        """
        # Freeze mutable list fields by replacing with tuples
        # We reassign via object.__setattr__ to bypass our own __setattr__ guard
        object.__setattr__(self, "allowed_paths", tuple(self.allowed_paths))
        object.__setattr__(self, "allowed_actions", tuple(self.allowed_actions))
        object.__setattr__(self, "forbidden_paths", tuple(self.forbidden_paths))
        self._locked = True

    @property
    def is_locked(self) -> bool:
        return self._locked

    def __setattr__(self, name: str, value) -> None:
        """Override to block all field mutations when scope is locked."""
        # Allow setting private attrs and initial construction
        if name.startswith("_"):
            object.__setattr__(self, name, value)
            return
        if getattr(self, "_locked", False):
            raise ScopeLockError(
                f"Scope is locked and immutable. "
                f"Attempted mutation of field '{name}' is strictly prohibited. "
                "[SCOPE_HASH_MISMATCH]"
            )
        super().__setattr__(name, value)

    def check_mutation_allowed(self) -> None:
        if self.is_locked:
            raise ScopeLockError("Scope is locked and immutable. Scope expansion is strictly prohibited.")

    def add_allowed_path(self, path: str) -> None:
        self.check_mutation_allowed()
        # When unlocked allowed_paths is still a list
        if isinstance(self.allowed_paths, (list,)):
            canonical = unicodedata.normalize('NFC', str(path)).replace('\\', '/').strip()
            self.allowed_paths.append(canonical)
        else:
            raise ScopeLockError("Scope is locked — cannot add allowed path.")

    def compute_hash(self) -> str:
        """Computes deterministic SHA-256 hash of canonical scope state."""
        canonical_dict = {
            "workspace_root": unicodedata.normalize('NFC', str(Path(self.workspace_root).resolve()).replace("\\", "/")),
            "allowed_paths": sorted([str(p).replace("\\", "/") for p in self.allowed_paths]),
            "allowed_actions": sorted(list(self.allowed_actions)),
            "forbidden_paths": sorted([str(p).replace("\\", "/") for p in self.forbidden_paths]),
            "max_files": self.max_files,
            "max_bytes": self.max_bytes,
            "max_operations": self.max_operations,
            "allow_create": self.allow_create,
            "allow_modify": self.allow_modify,
            "allow_delete": self.allow_delete,
            "allow_rename": self.allow_rename,
            "allow_git_commit": self.allow_git_commit,
            "allow_git_push": self.allow_git_push,
            "allow_sensitive": self.allow_sensitive,
        }
        encoded = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def is_path_in_scope(self, target_path: Union[str, Path]) -> bool:
        """
        Validates whether target_path falls within the authorized allowed_paths
        and is not in forbidden_paths or sensitive locations.
        """
        try:
            resolved_ws = Path(self.workspace_root).resolve()
            resolved_target = resolve_and_validate_path(target_path, resolved_ws)
        except SecurityPathError:
            return False

        # Check sensitive paths: forbidden unless allow_sensitive is explicitly True
        if is_sensitive_path(resolved_target) and not self.allow_sensitive:
            return False

        # Check forbidden paths
        for fp in self.forbidden_paths:
            fp_resolved = (resolved_ws / fp).resolve()
            if resolved_target == fp_resolved:
                return False
            try:
                resolved_target.relative_to(fp_resolved)
                return False
            except ValueError:
                pass

        # If allowed_paths is empty, deny
        if not self.allowed_paths:
            return False

        # Check allowed paths
        for ap in self.allowed_paths:
            ap_resolved = (resolved_ws / ap).resolve()
            if resolved_target == ap_resolved:
                return True
            try:
                resolved_target.relative_to(ap_resolved)
                return True
            except ValueError:
                pass

        return False
