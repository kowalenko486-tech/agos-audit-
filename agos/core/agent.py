"""AGOS 3.1 Hardened Agent Orchestrator."""
import os
import json
from typing import Optional, Callable, Dict, Any, List
from dotenv import load_dotenv
from openai import OpenAI
from agos.core.router import ToolRegistry
from agos.core.models import Evidence, VerifiedStatement
from agos.core.operation import Operation
from agos.security.prompt_guard import context_firewall
from agos.security.dlp import dlp_engine, DLPMode, TokenVault
from agos.security.llm_output_guard import (
    AgentResourceLimits,
    ModelDoSError,
    OutputGuardMode,
    ToolCallValidationError,
    llm_output_guard,
    parse_and_validate_tool_arguments,
)

load_dotenv()

class AgosAgent:
    def __init__(
        self,
        registry: ToolRegistry,
        model: str = os.getenv("AGOS_LLM_MODEL", "gemini-3.5-flash"),
        llm_mock: Optional[Callable[[str], dict]] = None,
        system_prompt: Optional[str] = None,
        use_firewall: bool = True,
        dlp_mode: Optional[DLPMode] = None,
        deanonymize_response: bool = True,
        output_guard_mode: Optional[OutputGuardMode] = None,
        max_turns: Optional[int] = None,
        max_tool_calls_per_turn: Optional[int] = None,
        max_context_chars: Optional[int] = None,
    ):
        # F-07: the mock path skips DLP/ContextFirewall — allowed only when explicitly enabled (tests).
        if llm_mock is not None and os.environ.get("AGOS_ALLOW_LLM_MOCK") != "1":
            raise RuntimeError(
                "llm_mock bypasses DLP and ContextFirewall; set AGOS_ALLOW_LLM_MOCK=1 (test environments only)."
            )
        self.registry = registry
        self.model = model
        self.llm_mock = llm_mock
        self.system_prompt = system_prompt
        self.use_firewall = use_firewall
        self.dlp_mode = dlp_mode
        self.deanonymize_response = deanonymize_response
        self.output_guard_mode = output_guard_mode
        self.limits = AgentResourceLimits.from_env(
            max_turns=max_turns,
            max_tool_calls_per_turn=max_tool_calls_per_turn,
            max_context_chars=max_context_chars,
        )
        self._client: Optional[OpenAI] = None

    @property
    def client(self) -> OpenAI:
        if self._client is None:
            self._client = OpenAI(
                api_key=os.getenv("GEMINI_API_KEY", "mock-api-key"),
                base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
            )
        return self._client

    def _get_openai_tools(self) -> list:
        registered_tools = getattr(self.registry, '_tools', {})
        tools = []
        for name, tool in registered_tools.items():
            schema = {
                "type": "function",
                "function": {
                    "name": name,
                    "description": getattr(tool, "description", f"Wykonuje bezpieczne narzędzie: {name}")
                }
            }
            if hasattr(tool, 'parameters'):
                schema["function"]["parameters"] = tool.parameters
            tools.append(schema)
        return tools

    def run(self, prompt: str, operation: Optional[Operation] = None) -> VerifiedStatement:
        """
        Executes an agent run loop and returns a cryptographically VerifiedStatement.
        Supports both mocked execution for testing and live LLM calls.
        """
        if self.llm_mock:
            mock_res = self.llm_mock(prompt)
            evidences: List[Evidence] = []
            if "tool_call" in mock_res:
                tc = mock_res["tool_call"]
                t_name = tc.get("name")
                t_kwargs = tc.get("kwargs", {})
                t_result = self.registry.execute_tool(t_name, operation=operation, **t_kwargs)
                if "provenance_hash" in t_result:
                    evidences.append(Evidence(**t_result))

            raw_claim = mock_res.get("claim", "Brak tezy")
            safe_claim, _ = llm_output_guard.sanitize_output(
                raw_claim, mode_override=self.output_guard_mode
            )
            return VerifiedStatement(
                claim=safe_claim,
                evidences=evidences
            )

        # Live execution fallback to process_intent
        intent_res = self.process_intent(prompt, operation=operation)
        evidences = []
        for exec_info in intent_res.get("tool_executions", []):
            ev_data = exec_info.get("evidence", {})
            if "provenance_hash" in ev_data:
                evidences.append(Evidence(**ev_data))

        return VerifiedStatement(
            claim=intent_res.get("claim", ""),
            evidences=evidences
        )

    @staticmethod
    def _estimate_context_chars(messages: list) -> int:
        total = 0
        for m in messages:
            if isinstance(m, dict):
                total += len(str(m.get("content", "")))
            else:
                total += len(str(getattr(m, "content", "") or ""))
        return total

    def process_intent(self, prompt: str, operation: Optional[Operation] = None) -> dict:
        """
        Multi-turn LLM intent processing loop enforcing AGOS tool execution,
        Model DoS resource limits, fail-closed tool argument validation, and output secret scanning.
        """
        if self.llm_mock:
            mock_res = self.llm_mock(prompt)
            results = []
            if "tool_call" in mock_res:
                tc = mock_res["tool_call"]
                t_name = tc.get("name")
                t_kwargs = tc.get("kwargs", {})
                t_result = self.registry.execute_tool(t_name, operation=operation, **t_kwargs)
                results.append({"tool": t_name, "evidence": t_result})
            raw_claim = mock_res.get("claim", "")
            safe_claim, _ = llm_output_guard.sanitize_output(
                raw_claim, mode_override=self.output_guard_mode
            )
            return {
                "claim": safe_claim,
                "tool_executions": results
            }

        tools = self._get_openai_tools()
        messages = []
        vault = TokenVault()

        # ── Egress DLP (Layer 0) — protect PII/secrets before LLM API ─────────
        dlp_prompt_res = dlp_engine.scan_and_process(
            prompt, vault=vault, mode_override=self.dlp_mode
        )
        dlp_clean_prompt = dlp_prompt_res.sanitized_text

        # ── ContextFirewall integration ───────────────────────────────────────
        # Każdy user_prompt przechodzi przez 3-warstwową obronę przed
        # prompt injection zanim trafi do LLM (tylko w trybie live).
        if self.use_firewall:
            base_system = self.system_prompt or ""
            reinforced_system, safe_prompt = context_firewall.process(
                dlp_clean_prompt, base_system
            )
            if reinforced_system:
                messages.append({"role": "system", "content": reinforced_system})
            effective_prompt = safe_prompt
        else:
            # Firewall wyłączony (np. tryb debug) — bez modyfikacji
            if self.system_prompt:
                messages.append({"role": "system", "content": self.system_prompt})
            effective_prompt = dlp_clean_prompt
        # ─────────────────────────────────────────────────────────────────────

        messages.append({"role": "user", "content": effective_prompt})
        results = []
        turn_count = 0

        while True:
            turn_count += 1
            if turn_count > self.limits.max_turns:
                raise ModelDoSError(
                    f"[MODEL_DOS_GUARD] Exceeded maximum agent turns ({self.limits.max_turns}). "
                    f"Operation aborted to prevent unbounded LLM consumption."
                )

            ctx_chars = self._estimate_context_chars(messages)
            if ctx_chars > self.limits.max_context_chars:
                raise ModelDoSError(
                    f"[MODEL_DOS_GUARD] Context size ({ctx_chars} chars) exceeds limit "
                    f"({self.limits.max_context_chars} chars)."
                )

            models_to_try = [self.model, "gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-flash-latest"]
            seen_models = set()
            ordered_models = [m for m in models_to_try if not (m in seen_models or seen_models.add(m))]
            last_err = None
            response = None
            for m in ordered_models:
                try:
                    call_kwargs = {"model": m, "messages": messages}
                    if tools:
                        call_kwargs["tools"] = tools
                    response = self.client.chat.completions.create(**call_kwargs)
                    break
                except Exception as ex:
                    last_err = ex
                    err_str = str(ex)
                    if any(code in err_str for code in ("503", "UNAVAILABLE", "404", "NOT_FOUND", "429")):
                        continue
                    raise
            if response is None:
                raise last_err
            message = response.choices[0].message

            if not message.tool_calls:
                final_claim = message.content or ""
                if self.deanonymize_response and vault.size > 0:
                    final_claim = vault.deanonymize(final_claim)
                final_claim, _ = llm_output_guard.sanitize_output(
                    final_claim, mode_override=self.output_guard_mode
                )
                return {
                    "claim": final_claim,
                    "tool_executions": results
                }

            if len(message.tool_calls) > self.limits.max_tool_calls_per_turn:
                raise ModelDoSError(
                    f"[MODEL_DOS_GUARD] LLM requested {len(message.tool_calls)} tool calls in a single turn, "
                    f"exceeding limit ({self.limits.max_tool_calls_per_turn})."
                )

            messages.append(message)

            for tool_call in message.tool_calls:
                name = tool_call.function.name
                tool_obj = self.registry.get_tool(name)
                schema = getattr(tool_obj, "parameters", None) if tool_obj else None

                try:
                    args = parse_and_validate_tool_arguments(
                        tool_call.function.arguments,
                        tool_name=name,
                        schema=schema,
                    )
                    tool_result = self.registry.execute_tool(name, operation=operation, **args)
                except ToolCallValidationError as val_err:
                    # Fail-closed: never execute tool when LLM arguments fail JSON parsing or schema check
                    tool_result = {
                        "error": f"Odmowa walidacji argumentów AGOS: {val_err}",
                        "decision": "DENY",
                        "reason_code": "INVALID_TOOL_ARGUMENTS",
                    }

                results.append({
                    "tool": name,
                    "evidence": tool_result
                })

                egress_tool_json = dlp_engine.scan_and_process(
                    json.dumps(tool_result),
                    vault=vault,
                    mode_override=self.dlp_mode,
                ).sanitized_text

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "name": name,
                    "content": egress_tool_json
                })


