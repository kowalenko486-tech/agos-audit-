"""Tests for Phase 3: Zero-Trust for LLM Responses (Tool Argument Validation, Model DoS Limits, Output Secret Guard)."""
from types import SimpleNamespace
import pytest

from agos.core.agent import AgosAgent
from agos.core.router import ToolRegistry
from agos.core.provenance import TrustedTool
from agos.tools.scanner import ProjectScannerTool
from agos.tools.security import SecurityScannerTool
from agos.security.llm_output_guard import (
    LLMOutputGuard,
    ModelDoSError,
    OutputGuardMode,
    ToolCallValidationError,
    parse_and_validate_tool_arguments,
)


# ── 1. Tool-Call Argument Schema & Null-Byte Validation ──────────────────────

def test_parse_tool_arguments_rejects_malformed_json():
    with pytest.raises(ToolCallValidationError) as exc_info:
        parse_and_validate_tool_arguments("{broken_json:", tool_name="security_scanner")
    assert "TOOL_ARG_INVALID_JSON" in str(exc_info.value)


def test_parse_tool_arguments_rejects_non_object_json():
    with pytest.raises(ToolCallValidationError) as exc_info:
        parse_and_validate_tool_arguments('["list", "not", "dict"]', tool_name="security_scanner")
    assert "TOOL_ARG_NOT_OBJECT" in str(exc_info.value)


def test_parse_tool_arguments_rejects_null_byte_injection():
    with pytest.raises(ToolCallValidationError) as exc_info:
        parse_and_validate_tool_arguments(
            {"filepath": "module.py\x00.txt"},
            tool_name="security_scanner",
        )
    assert "TOOL_ARG_NULL_BYTE" in str(exc_info.value)


def test_router_enforces_required_and_type_schema(tmp_path):
    registry = ToolRegistry()
    registry.register(SecurityScannerTool(workspace_root=tmp_path))
    registry.register(ProjectScannerTool(workspace_root=tmp_path))

    # Missing required 'filepath' for security_scanner
    res_missing = registry.execute_tool("security_scanner")
    assert res_missing["decision"] == "DENY"
    assert res_missing["reason_code"] == "INVALID_TOOL_ARGUMENTS"
    assert "TOOL_ARG_MISSING_REQUIRED" in res_missing["error"]

    # Wrong type for 'max_depth' (string instead of integer) for project_scanner
    res_type = registry.execute_tool("project_scanner", directory=".", max_depth="deep")
    assert res_type["decision"] == "DENY"
    assert res_type["reason_code"] == "INVALID_TOOL_ARGUMENTS"
    assert "TOOL_ARG_TYPE_MISMATCH" in res_type["error"]

    # Boolean passed where integer is expected (bool is subclass of int in Python)
    res_bool = registry.execute_tool("project_scanner", directory=".", max_depth=True)
    assert res_bool["decision"] == "DENY"
    assert res_bool["reason_code"] == "INVALID_TOOL_ARGUMENTS"


def test_agent_blocks_malformed_json_tool_call_without_executing_tool():
    executed = False

    class _DummyTool(TrustedTool):
        def __init__(self):
            super().__init__(name="dummy_tool")
            self.parameters = {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            }

        def execute(self, query: str = "default") -> str:
            nonlocal executed
            executed = True
            return f"ran:{query}"

    registry = ToolRegistry()
    registry.register(_DummyTool())

    class _FakeCompletions:
        def __init__(self):
            self.turn = 0

        def create(self, **kwargs):
            self.turn += 1
            if self.turn == 1:
                tc = SimpleNamespace(
                    id="call_bad_json",
                    function=SimpleNamespace(name="dummy_tool", arguments="{malformed_json"),
                )
                msg = SimpleNamespace(content=None, tool_calls=[tc])
            else:
                msg = SimpleNamespace(content="Zakończono po błędzie argumentów.", tool_calls=None)
            return SimpleNamespace(choices=[SimpleNamespace(message=msg)])

    agent = AgosAgent(registry=registry)
    agent._client = SimpleNamespace(chat=SimpleNamespace(completions=_FakeCompletions()))

    res = agent.process_intent("Test uszkodzonego JSON")
    assert executed is False
    assert res["tool_executions"][0]["evidence"]["reason_code"] == "INVALID_TOOL_ARGUMENTS"


# ── 2. Model DoS Resource Limits (Turns, Fan-out, Context Size) ──────────────

class _NoopTool(TrustedTool):
    def __init__(self):
        super().__init__(name="noop")

    def execute(self) -> str:
        return "ok"


def test_agent_aborts_on_infinite_tool_loop_max_turns():
    registry = ToolRegistry()
    registry.register(_NoopTool())

    class _InfiniteLoopCompletions:
        def create(self, **kwargs):
            tc = SimpleNamespace(
                id="call_loop",
                function=SimpleNamespace(name="noop", arguments="{}"),
            )
            msg = SimpleNamespace(content=None, tool_calls=[tc])
            return SimpleNamespace(choices=[SimpleNamespace(message=msg)])

    agent = AgosAgent(registry=registry, max_turns=3)
    agent._client = SimpleNamespace(chat=SimpleNamespace(completions=_InfiniteLoopCompletions()))

    with pytest.raises(ModelDoSError) as exc_info:
        agent.process_intent("Run forever")
    assert "Exceeded maximum agent turns (3)" in str(exc_info.value)


def test_agent_aborts_on_excessive_tool_calls_per_turn():
    registry = ToolRegistry()
    registry.register(_NoopTool())

    class _FanOutCompletions:
        def create(self, **kwargs):
            tcs = [
                SimpleNamespace(id=f"c_{i}", function=SimpleNamespace(name="noop", arguments="{}"))
                for i in range(6)
            ]
            msg = SimpleNamespace(content=None, tool_calls=tcs)
            return SimpleNamespace(choices=[SimpleNamespace(message=msg)])

    agent = AgosAgent(registry=registry, max_tool_calls_per_turn=3)
    agent._client = SimpleNamespace(chat=SimpleNamespace(completions=_FanOutCompletions()))

    with pytest.raises(ModelDoSError) as exc_info:
        agent.process_intent("Trigger fan-out")
    assert "exceeding limit (3)" in str(exc_info.value)


def test_agent_aborts_when_context_chars_exceed_limit():
    registry = ToolRegistry()
    agent = AgosAgent(registry=registry, max_context_chars=50)
    with pytest.raises(ModelDoSError) as exc_info:
        agent.process_intent("A" * 100)
    assert "Context size" in str(exc_info.value)


# ── 3. LLM Output Secret Leakage Guard ───────────────────────────────────────

def test_output_guard_redacts_provenance_secret_and_api_keys(monkeypatch):
    monkeypatch.setenv("AGOS_PROVENANCE_SECRET", "super-secret-hmac-key-minimum-32-bytes-long!!")
    guard = LLMOutputGuard(mode=OutputGuardMode.ENFORCE)

    leaked_response = (
        "Oto sekret systemowy: super-secret-hmac-key-minimum-32-bytes-long!! "
        "oraz klucz OpenAI: sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456"
    )
    sanitized, detections = guard.sanitize_output(leaked_response)

    assert "super-secret-hmac-key-minimum-32-bytes-long!!" not in sanitized
    assert "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456" not in sanitized
    assert "[REDACTED_SYSTEM_SECRET]" in sanitized
    assert "[REDACTED_SECRET:OpenAI API Key Literal]" in sanitized
    assert "AGOS_PROVENANCE_SECRET Leak" in detections
