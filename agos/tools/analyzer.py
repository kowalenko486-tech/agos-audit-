"""AGOS 3.1 Hardened Python Static Analyzer Tool."""
import ast
from pathlib import Path
from typing import Optional, Union
from agos.core.provenance import TrustedTool
from agos.security.capabilities import Capability
from agos.security.paths import resolve_and_validate_path, SecurityPathError
from agos.core.operation import Operation
from agos.core.policy import policy_engine, PolicyDecision

class PythonStaticAnalyzerTool(TrustedTool):
    """
    Hardened Python Static Analyzer Tool.
    Capability: ANALYZE
    Enforces:
    - Path boundary check
    - Policy authorization
    - AST validation
    """

    def __init__(self, workspace_root: Optional[Union[str, Path]] = None):
        super().__init__(name="python_static_analyzer")
        self.capability = Capability.ANALYZE
        self._custom_workspace = Path(workspace_root).resolve() if workspace_root else None
        self.description = "Wykonuje statyczną analizę kodu Python (AST) w poszukiwaniu błędów składniowych."
        self.parameters = {
            "type": "object",
            "properties": {
                "filepath": {"type": "string", "description": "Ścieżka do pliku .py"}
            },
            "required": ["filepath"]
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

    def execute(self, filepath: str, operation: Optional[Operation] = None, **kwargs) -> str:
        ws = Path(operation.scope.workspace_root).resolve() if operation else self.workspace_root
        try:
            resolved_path = resolve_and_validate_path(filepath, ws, must_exist=True)
        except SecurityPathError as spe:
            return f"[BŁĄD BEZPIECZEŃSTWA] {spe}"

        # Policy check
        decision = policy_engine.authorize(
            capability=self.capability,
            operation=operation,
            target_path=resolved_path,
            actor="agent",
        )
        if decision.decision != PolicyDecision.ALLOW:
            return f"[ODMOWA POLITYKI] {decision.reason}"

        try:
            with open(resolved_path, 'r', encoding='utf-8-sig') as f:
                source = f.read()
            ast.parse(source)
            return f"[SUKCES] Plik {filepath} nie zawiera błędów składniowych na poziomie AST."
        except SyntaxError as e:
            return f"[BŁĄD SKŁADNI] Plik {filepath}, linia {e.lineno}: {e.msg}"
        except Exception as e:
            return f"[BŁĄD SYSTEMU] Nie można przeanalizować pliku: {str(e)}"
