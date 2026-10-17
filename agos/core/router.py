"""AGOS 3.1 Tool Registry and Central Policy Interceptor."""
import inspect
import logging
from typing import Dict, Any, List, Optional
from agos.core.provenance import TrustedTool
from agos.core.policy import policy_engine, PolicyDecision
from agos.core.operation import Operation
from agos.core.audit import audit_trail
from agos.security.capabilities import Capability

logger = logging.getLogger(__name__)

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, TrustedTool] = {}
        # Validate provenance secret at startup
        try:
            from agos.core.provenance import validate_provenance_secret_at_startup
            validate_provenance_secret_at_startup()
        except RuntimeError as e:
            import logging
            logging.getLogger('agos.core.router').warning(
                f'[AGOS] Provenance secret validation warning: {e}'
            )

    def register(self, tool: TrustedTool):
        """Registers a new trusted tool in the registry."""
        self._tools[tool.name] = tool

    def get_registered_tool_names(self) -> List[str]:
        """Returns list of registered tool names."""
        return list(self._tools.keys())

    def get_tool(self, name: str) -> Optional[TrustedTool]:
        return self._tools.get(name)

    def execute_tool(self, name: str, operation: Optional[Operation] = None, **kwargs) -> Dict[str, Any]:
        """
        Executes a registered tool under strict Policy Engine authorization.
        Fails closed on any security or policy violation.
        MED-02: Explicit architectural guard blocks mutation without operation context
        before reaching PolicyEngine — defense in depth.
        """
        if name not in self._tools:
            return {"error": f"Odmowa systemu: Narzędzie '{name}' nie jest zarejestrowane."}

        tool = self._tools[name]
        capability = getattr(tool, "capability", Capability.ANALYZE)
        target = kwargs.get("filepath") or kwargs.get("directory") or kwargs.get("files") or ""

        # Phase 3: Zero-Trust Tool Argument Schema & Null-Byte Validation
        try:
            from agos.security.llm_output_guard import (
                parse_and_validate_tool_arguments,
                ToolCallValidationError,
            )
            parse_and_validate_tool_arguments(
                kwargs,
                tool_name=name,
                schema=getattr(tool, "parameters", None),
            )
        except ToolCallValidationError as val_err:
            reason = f"INV-028/LLM05: Tool argument validation failed for '{name}': {val_err}"
            logger.warning(reason)
            audit_trail.record(
                operation_id=operation.operation_id if operation else "NO-OP",
                state=str(operation.state) if operation else "UNKNOWN",
                action=str(capability),
                target=str(target),
                result="DENY",
                reason=reason,
            )
            return {
                "error": f"Odmowa walidacji argumentów AGOS: {val_err}",
                "decision": "DENY",
                "reason_code": "INVALID_TOOL_ARGUMENTS",
                "operation_id": operation.operation_id if operation else "NO-OP",
            }

        # MED-02 / INV-023: Architectural guard — mutation without operation is ALWAYS denied
        if operation is None and Capability.is_mutation(capability):
            reason = (
                f"INV-023: Direct tool mutation bypass attempt — tool '{name}' with "
                f"capability '{capability}' requires an active Operation context. "
                "[DIRECT_TOOL_BYPASS]"
            )
            logger.warning(reason)
            audit_trail.record(
                operation_id="NO-OP",
                state="UNKNOWN",
                action=str(capability),
                target=str(target),
                result="DENY",
                reason=reason,
            )
            return {
                "error": f"Odmowa polityki AGOS: {reason}",
                "decision": "DENY",
                "reason_code": "DIRECT_TOOL_BYPASS",
                "operation_id": "NO-OP",
            }

        # 1. Central Policy Authorization Interceptor
        decision = policy_engine.authorize(
            capability=capability,
            operation=operation,
            target_path=target if isinstance(target, str) else None,
            actor="agent",
        )

        if decision.decision != PolicyDecision.ALLOW:
            logger.warning(f"Policy Engine DENIED execution of tool '{name}': {decision.reason}")
            return {
                "error": f"Odmowa polityki AGOS: {decision.reason}",
                "decision": decision.decision.value,
                "reason_code": getattr(decision, "reason_code", "POLICY_ERROR"),
                "operation_id": decision.operation_id,
            }

        # 2. Execution under failure isolation
        try:
            # Check if tool.execute accepts 'operation'
            sig = inspect.signature(tool.execute)
            call_kwargs = dict(kwargs)
            has_op = "operation" in sig.parameters or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
            if has_op and operation is not None:
                call_kwargs["operation"] = operation

            tool_res = tool.run_and_sign(**call_kwargs)
            return tool_res
        except Exception as e:
            logger.error(f"Krytyczny błąd narzędzia '{name}': {e}")
            audit_trail.record(
                operation_id=operation.operation_id if operation else "NO-OP",
                state=str(operation.state) if operation else "UNKNOWN",
                action=str(capability),
                target=str(target),
                result="FAIL",
                reason=f"Tool internal failure: {str(e)}"
            )
            return {"error": f"Błąd wewnętrzny narzędzia: {str(e)}"}
