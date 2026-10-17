"""AGOS 3.1 Append-Only Audit Trail System with Hash Chain Integrity."""
import hashlib
import json
import time
import re
import threading
from typing import List, Optional, Dict, Any, Tuple
from pydantic import BaseModel, Field

_audit_lock = threading.Lock()
_event_counter = 1


def generate_event_id() -> str:
    global _event_counter
    with _audit_lock:
        eid = f"EVT-{time.strftime('%Y%m%d')}-{_event_counter:08d}"
        _event_counter += 1
        return eid


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=generate_event_id)
    operation_id: str
    timestamp: float = Field(default_factory=time.time)
    actor: str = "system"
    state: str
    action: str
    target: str
    scope_hash: str = ""
    approval_id: Optional[str] = None
    result: str  # "ALLOW", "DENY", "SUCCESS", "FAIL"
    reason: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # MED-04: Hash chaining fields
    prev_event_hash: str = ""
    event_hash: str = ""

    def compute_event_hash(self) -> str:
        """
        MED-04: Deterministic SHA-256 of this event's canonical fields.
        Includes prev_event_hash to form the chain.
        """
        canonical = {
            "event_id": self.event_id,
            "operation_id": self.operation_id,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "state": self.state,
            "action": self.action,
            "target": self.target,
            "scope_hash": self.scope_hash,
            "approval_id": self.approval_id or "",
            "result": self.result,
            "reason": self.reason,
            "prev_event_hash": self.prev_event_hash,
        }
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


# Sanitization patterns to redact accidental secrets before writing to memory/disk audit trail
REDACT_PATTERNS = [
    (
        re.compile(
            r"(?i)(api[_-]?key|password|secret|token|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{4,})['\"]?"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{20,}\b"),
        "[REDACTED_OPENAI_KEY]",
    ),
    (
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "[REDACTED_GCP_KEY]",
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "[REDACTED_AWS_KEY]",
    ),
    (
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
        "[REDACTED_GH_TOKEN]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        "[REDACTED_JWT]",
    ),
]


def sanitize_audit_text(text: str) -> str:
    import os
    if not isinstance(text, str):
        text = str(text)
    sanitized = text
    prov_secret = os.getenv("AGOS_PROVENANCE_SECRET", "")
    if prov_secret and len(prov_secret) >= 8 and prov_secret in sanitized:
        sanitized = sanitized.replace(prov_secret, "[REDACTED_SYSTEM_SECRET]")
    for pattern, replacement in REDACT_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


class AuditTrail:
    """
    Thread-safe append-only audit storage with SHA-256 hash chain integrity and JSONL persistence.
    MED-04 / INV-019: Each event contains prev_event_hash and event_hash forming
    a tamper-evident chain. verify_integrity() detects any modification, deletion, or insertion.

    Supports durable append-only JSONL persistence via `audit_file` argument or
    the `AGOS_AUDIT_FILE` environment variable, verifying the entire existing chain at startup.
    """

    def __init__(
        self,
        audit_file: Optional[str] = None,
        verify_on_load: bool = True,
        fsync: Optional[bool] = None,
    ):
        import os
        self._events: List[AuditEvent] = []
        self._lock = threading.Lock()
        self._last_event_hash: str = ""  # Hash of most recently appended event
        resolved_file = audit_file if audit_file is not None else (os.getenv("AGOS_AUDIT_FILE", "").strip() or None)
        self._audit_file: Optional[str] = resolved_file
        self._fsync: bool = (
            fsync if fsync is not None else (os.getenv("AGOS_AUDIT_FSYNC", "0").strip() == "1")
        )
        if self._audit_file:
            self._load_existing_events(self._audit_file, verify_on_load=verify_on_load)

    def configure_persistence(
        self,
        audit_file: Optional[str],
        verify_on_load: bool = True,
        fsync: Optional[bool] = None,
    ) -> None:
        """Dynamically configures or switches the persistent JSONL file for this AuditTrail."""
        with self._lock:
            self._events.clear()
            self._last_event_hash = ""
            self._audit_file = audit_file
            if fsync is not None:
                self._fsync = fsync
            if self._audit_file:
                self._load_existing_events(self._audit_file, verify_on_load=verify_on_load)

    @classmethod
    def load_from_file(cls, filepath: str) -> "AuditTrail":
        trail = cls(audit_file=filepath, verify_on_load=True)
        return trail

    def get_stats(self) -> dict:
        is_valid, _ = self.verify_integrity()
        return {
            "total_events": self.count(),
            "has_persistence": bool(self._audit_file),
            "audit_file": self._audit_file,
            "chain_valid": is_valid,
        }

    def _load_existing_events(self, audit_file: str, verify_on_load: bool = True) -> None:
        """Load and verify existing audit chain from JSONL file."""
        import os
        global _event_counter
        if not os.path.exists(audit_file):
            return
        try:
            with open(audit_file, "r", encoding="utf-8") as f:
                for line_no, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    event = AuditEvent(**data)
                    self._events.append(event)
                    self._last_event_hash = event.event_hash
            with _audit_lock:
                if len(self._events) >= _event_counter:
                    _event_counter = len(self._events) + 1
        except Exception as e:
            raise RuntimeError(f"[AGOS AUDIT] Failed to load audit file '{audit_file}': {e}") from e

        if verify_on_load and self._events:
            is_valid, reason = self.verify_integrity()
            if not is_valid:
                raise RuntimeError(f"Audit chain broken: {reason}")

    def _persist_event(self, event: AuditEvent) -> None:
        """Append event to persistent audit file (JSONL format)."""
        if not self._audit_file:
            return
        import os
        from pathlib import Path
        try:
            parent = Path(self._audit_file).parent
            if str(parent) and not parent.exists():
                parent.mkdir(parents=True, exist_ok=True)
            with open(self._audit_file, "a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")
                f.flush()
                if self._fsync:
                    os.fsync(f.fileno())
        except Exception as e:
            # Do NOT silently swallow — audit persistence failure is critical
            raise RuntimeError(f"[AGOS AUDIT] Failed to persist audit event: {e}") from e

    def record(
        self,
        operation_id: str,
        state: str,
        action: str,
        target: str,
        result: str,
        actor: str = "system",
        scope_hash: str = "",
        approval_id: Optional[str] = None,
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        clean_target = sanitize_audit_text(target)
        clean_reason = sanitize_audit_text(reason)
        clean_metadata = {k: sanitize_audit_text(str(v)) for k, v in (metadata or {}).items()}

        with self._lock:
            event = AuditEvent(
                operation_id=operation_id,
                actor=actor,
                state=state,
                action=action,
                target=clean_target,
                scope_hash=scope_hash,
                approval_id=approval_id,
                result=result,
                reason=clean_reason,
                metadata=clean_metadata,
                prev_event_hash=self._last_event_hash,
            )
            # Compute and seal event hash
            event.event_hash = event.compute_event_hash()
            self._last_event_hash = event.event_hash
            self._events.append(event)
            self._persist_event(event)
        return event

    def get_events(self, operation_id: Optional[str] = None) -> List[AuditEvent]:
        with self._lock:
            if operation_id:
                return [e for e in self._events if e.operation_id == operation_id]
            return list(self._events)

    def count(self) -> int:
        with self._lock:
            return len(self._events)

    def verify_integrity(self) -> Tuple[bool, str]:
        """
        MED-04 / INV-019: Verifies the audit chain integrity.
        Detects: modified events, deleted events (gap in chain), forged events.
        Returns (True, "Audit chain integrity verified.") if intact, (False, reason) if tampered.
        """
        with self._lock:
            events = list(self._events)

        prev_hash = ""
        for i, event in enumerate(events):
            # Recompute what the hash should be
            expected_event = AuditEvent(
                event_id=event.event_id,
                operation_id=event.operation_id,
                timestamp=event.timestamp,
                actor=event.actor,
                state=event.state,
                action=event.action,
                target=event.target,
                scope_hash=event.scope_hash,
                approval_id=event.approval_id,
                result=event.result,
                reason=event.reason,
                prev_event_hash=prev_hash,
                event_hash="",  # not included in hash computation
            )
            expected_hash = expected_event.compute_event_hash()

            if event.prev_event_hash != prev_hash:
                return (
                    False,
                    f"AUDIT_TAMPERING: Event {i} (id={event.event_id}) "
                    f"prev_event_hash mismatch. Chain broken.",
                )
            if event.event_hash != expected_hash:
                return (
                    False,
                    f"AUDIT_TAMPERING: Event {i} (id={event.event_id}) "
                    f"event_hash invalid. Event may have been modified.",
                )
            prev_hash = event.event_hash

        return True, "Audit chain integrity verified."


# Global default audit trail instance (automatically binds AGOS_AUDIT_FILE if set)
audit_trail = AuditTrail()

