"""AGOS 3.2 Dynamic Workspace Manager (Zero-Trust)."""
import os
import threading
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("agos.workspace")


class WorkspaceManager:
    """
    Manages the active workspace root for AGOS tools.
    Allows dynamic runtime switching between projects while preserving Zero-Trust boundaries.
    """

    def __init__(self, default_root: Optional[Path] = None):
        self._lock = threading.Lock()
        self._default_root = Path(
            default_root or Path(__file__).resolve().parent.parent.parent
        ).resolve()
        self._current_root = self._default_root

        # Support initialization from env var
        env_root = os.environ.get("AGOS_WORKSPACE_ROOT")
        if env_root and os.path.isdir(env_root):
            self._current_root = Path(env_root).resolve()

    def get_current_workspace(self) -> Path:
        with self._lock:
            return self._current_root

    def get_default_workspace(self) -> Path:
        with self._lock:
            return self._default_root

    def is_default(self) -> bool:
        with self._lock:
            return self._current_root == self._default_root

    def set_workspace(self, path_str: str) -> Path:
        """
        Switches the active workspace to target directory.
        Strict validation: path must exist, be a directory, and not be a system root.
        """
        with self._lock:
            target = Path(path_str).resolve()
            if not target.exists():
                raise ValueError(f"Katalog nie istnieje: {target}")
            if not target.is_dir():
                raise ValueError(f"Ścieżka musi być katalogiem: {target}")

            # Security guard against setting system root
            parts = target.parts
            if len(parts) <= 1:
                raise ValueError(f"Niedozwolone ustawienie dysku głównego jako workspace: {target}")
            if len(parts) >= 2 and parts[1].lower() in ("windows", "system32", "program files"):
                raise ValueError(f"Niedozwolone ustawienie katalogu systemowego jako workspace: {target}")

            self._current_root = target
            logger.info(f"[AGOS WorkspaceManager] Aktywny workspace przestawiony na: {target}")
            return self._current_root

    def reset_workspace(self) -> Path:
        """Resets active workspace to default AGOS core root."""
        with self._lock:
            self._current_root = self._default_root
            logger.info(f"[AGOS WorkspaceManager] Workspace zresetowany do domyślnego: {self._default_root}")
            return self._current_root


workspace_manager = WorkspaceManager()
