"""
AGOS 3.1/3.2 — Zero-Trust LLM Output & Tool-Call Guard (Phase 3).

Protects AGOS against untrusted or compromised LLM responses:
  1. Strict Tool-Call Argument Validation (OWASP LLM05: Improper Output Handling):
     - Fail-closed on malformed JSON (never falls back to empty `{}`).
     - Rejects null-byte (`\\x00`) injection in arguments.
     - Enforces JSON Schema `required` fields and primitive types from `tool.parameters`.
  2. Model Denial-of-Service (DoS) Resource Limits (OWASP LLM10: Unbounded Consumption):
     - Bounds maximum agent turns (`AGOS_MAX_AGENT_TURNS`, default 10).
     - Bounds maximum tool calls per turn (`AGOS_MAX_TOOL_CALLS_PER_TURN`, default 5).
     - Bounds total serialized message context size (`AGOS_MAX_CONTEXT_CHARS`, default 100000).
  3. LLM Output Secret Leakage Guard (OWASP LLM02 / LLM05):
     - Always strips any accidental leakage of `AGOS_PROVENANCE_SECRET`.
     - Redacts high-confidence secret literals (API keys, JWTs, private keys) in LLM output.
"""
import json
import logging
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("agos.security.llm_output_guard")


class OutputGuardMode(str, Enum):
    OFF = "off"
    WARN = "warn"
    ENFORCE = "enforce"

    @classmethod
    def from_env(cls) -> "OutputGuardMode":
        raw = os.getenv("AGOS_OUTPUT_GUARD_MODE", "enforce").strip().lower()
        for mode in cls:
            if mode.value == raw:
                return mode
        return cls.ENFORCE


class ModelDoSError(RuntimeError):
    """Raised when an LLM conversation exceeds turn, tool-call, or context size limits."""


class ToolCallValidationError(ValueError):
    """Raised when LLM-supplied tool call arguments fail JSON parsing or schema validation."""


@dataclass(frozen=True)
class AgentResourceLimits:
    max_turns: int = 10
    max_tool_calls_per_turn: int = 5
    max_context_chars: int = 100_000

    @classmethod
    def from_env(
        cls,
        max_turns: Optional[int] = None,
        max_tool_calls_per_turn: Optional[int] = None,
        max_context_chars: Optional[int] = None,
    ) -> "AgentResourceLimits":
        return cls(
            max_turns=max_turns if max_turns is not None else int(os.getenv("AGOS_MAX_AGENT_TURNS", "10")),
            max_tool_calls_per_turn=(
                max_tool_calls_per_turn
                if max_tool_calls_per_turn is not None
                else int(os.getenv("AGOS_MAX_TOOL_CALLS_PER_TURN", "5"))
            ),
            max_context_chars=(
                max_context_chars
                if max_context_chars is not None
                else int(os.getenv("AGOS_MAX_CONTEXT_CHARS", "100000"))
            ),
        )


_JSON_TYPE_MAP = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
}


def parse_and_validate_tool_arguments(
    raw_arguments: Any,
    tool_name: str,
    schema: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Fail-closed parser and validator for LLM-generated tool-call arguments.
    Raises ToolCallValidationError on invalid JSON, non-object payload, null bytes,
    missing required fields, or schema type mismatches.
    """
    if isinstance(raw_arguments, str):
        raw_str = raw_arguments.strip()
        if not raw_str:
            parsed: Any = {}
        else:
            try:
                parsed = json.loads(raw_str)
            except json.JSONDecodeError as jde:
                raise ToolCallValidationError(
                    f"[TOOL_ARG_INVALID_JSON] Tool '{tool_name}' received malformed JSON arguments: {jde.msg}"
                ) from jde
    elif isinstance(raw_arguments, dict):
        parsed = dict(raw_arguments)
    else:
        raise ToolCallValidationError(
            f"[TOOL_ARG_INVALID_TYPE] Tool '{tool_name}' arguments must be a JSON object, got {type(raw_arguments).__name__}."
        )

    if not isinstance(parsed, dict):
        raise ToolCallValidationError(
            f"[TOOL_ARG_NOT_OBJECT] Tool '{tool_name}' arguments must decode to a JSON object, got {type(parsed).__name__}."
        )

    # Null-byte recursive check
    def _check_no_null_bytes(val: Any, path: str) -> None:
        if isinstance(val, str):
            if "\x00" in val:
                raise ToolCallValidationError(
                    f"[TOOL_ARG_NULL_BYTE] Null byte detected in argument '{path}' for tool '{tool_name}'."
                )
        elif isinstance(val, list):
            for idx, item in enumerate(val):
                _check_no_null_bytes(item, f"{path}[{idx}]")
        elif isinstance(val, dict):
            for k, v in val.items():
                _check_no_null_bytes(v, f"{path}.{k}")

    for k, v in parsed.items():
        _check_no_null_bytes(v, k)

    # Validate against JSON Schema if present
    if schema and isinstance(schema, dict):
        required_fields = schema.get("required", [])
        for req in required_fields:
            if req not in parsed or parsed[req] is None:
                raise ToolCallValidationError(
                    f"[TOOL_ARG_MISSING_REQUIRED] Tool '{tool_name}' missing required argument '{req}'."
                )

        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for arg_name, arg_val in parsed.items():
                if arg_name not in properties:
                    if schema.get("additionalProperties") is False:
                        raise ToolCallValidationError(
                            f"[TOOL_ARG_UNEXPECTED_FIELD] Tool '{tool_name}' received unexpected argument '{arg_name}'."
                        )
                    continue
                prop_spec = properties[arg_name]
                expected_type_name = prop_spec.get("type") if isinstance(prop_spec, dict) else None
                if expected_type_name in _JSON_TYPE_MAP:
                    py_type = _JSON_TYPE_MAP[expected_type_name]
                    # Note: in Python bool is a subclass of int; guard against bool passing for integer/number
                    if expected_type_name in ("integer", "number") and isinstance(arg_val, bool):
                        raise ToolCallValidationError(
                            f"[TOOL_ARG_TYPE_MISMATCH] Argument '{arg_name}' for tool '{tool_name}' "
                            f"must be '{expected_type_name}', got 'bool'."
                        )
                    if not isinstance(arg_val, py_type):
                        raise ToolCallValidationError(
                            f"[TOOL_ARG_TYPE_MISMATCH] Argument '{arg_name}' for tool '{tool_name}' "
                            f"must be '{expected_type_name}', got '{type(arg_val).__name__}'."
                        )

    return parsed


class LLMOutputGuard:
    """
    Scans LLM textual output before returning it to the caller, preventing
    system secret leakage and credential exposure.
    """

    def __init__(self, mode: Optional[OutputGuardMode] = None) -> None:
        self._explicit_mode = mode

    @property
    def mode(self) -> OutputGuardMode:
        if self._explicit_mode is not None:
            return self._explicit_mode
        return OutputGuardMode.from_env()

    def sanitize_output(
        self,
        text: str,
        mode_override: Optional[OutputGuardMode] = None,
    ) -> Tuple[str, List[str]]:
        """
        Scans LLM response text and returns `(sanitized_text, detections)`.
        - Always redacts `AGOS_PROVENANCE_SECRET` if present in output (even in WARN mode).
        - Scans against `SECURITY_SCAN_PATTERNS` according to `OutputGuardMode`.
        """
        if not text:
            return text, []

        active_mode = mode_override if mode_override is not None else self.mode
        result = text
        detections: List[str] = []

        # 1. Unconditional protection against AGOS_PROVENANCE_SECRET exfiltration
        prov_secret = os.getenv("AGOS_PROVENANCE_SECRET", "")
        if prov_secret and len(prov_secret) >= 8 and prov_secret in result:
            result = result.replace(prov_secret, "[REDACTED_SYSTEM_SECRET]")
            detections.append("AGOS_PROVENANCE_SECRET Leak")
            logger.critical("[AGOS OutputGuard] Blocked leakage of AGOS_PROVENANCE_SECRET in LLM response!")

        if active_mode == OutputGuardMode.OFF:
            return result, detections

        # 2. Scan for high-risk secret patterns in LLM output
        from agos.tools.security import SECURITY_SCAN_PATTERNS
        for label, pattern in SECURITY_SCAN_PATTERNS.items():
            if re.search(pattern, result):
                detections.append(label)
                if active_mode == OutputGuardMode.ENFORCE:
                    result = re.sub(pattern, f"[REDACTED_SECRET:{label}]", result)

        if detections:
            if active_mode == OutputGuardMode.WARN:
                logger.warning(
                    f"[AGOS OutputGuard] Wykryto wzorce sekretów w odpowiedzi LLM ({detections}) w trybie WARN."
                )
            else:
                logger.warning(
                    f"[AGOS OutputGuard] Zamaskowano sekrety w odpowiedzi LLM: {detections}."
                )

        return result, detections


llm_output_guard = LLMOutputGuard()
