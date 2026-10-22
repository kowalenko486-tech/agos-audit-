"""Shared in-memory operation state for the AGOS HTTP API (process-local)."""
import threading
from typing import Any, Dict

from agos.core.operation import Operation

operations_lock = threading.Lock()
operations_store: Dict[str, Operation] = {}
# operation_id -> change proposal (content kept server-side; the client never re-sends it on apply)
proposals: Dict[str, Dict[str, Any]] = {}
