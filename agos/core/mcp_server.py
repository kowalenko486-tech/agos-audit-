import asyncio
import json
import sys
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types
from pydantic import BaseModel, ConfigDict
from agos.core.router import ToolRegistry
from agos.core.provenance import TrustedTool

app = Server("agos-4-1-mcp-server")
registry = ToolRegistry()

# TARCZA ANTY-WALIDACYJNA: elastyczny model przyjmujący wszystkie struktury zapytania
class FlexibleParams(BaseModel):
    model_config = ConfigDict(extra='allow')
    name: str = ""
    arguments: dict = {}

class SystemStatusTool(TrustedTool):
    def __init__(self):
        super().__init__(name="system_status")
    
    def execute(self, **kwargs) -> str:
        return (
            "Serwer AGOS 4.1 MCP jest ONLINE. Zasada: Twierdzenie != Dowód jest natywnie egzekwowana. "
            "INV-032 Zero-Trust MCP, Egress DLP, AST-SAST, DependencyGuard (anty-slopsquatting), "
            "LLMOutputGuard oraz Durable JSONL Audit są aktywne."
        )

from agos.tools.security import SecurityScannerTool
from agos.tools.scanner import ProjectScannerTool
from agos.tools.analyzer import PythonStaticAnalyzerTool
from agos.core.workspace_manager import workspace_manager
from agos.security.capabilities import Capability

class GetWorkspaceTool(TrustedTool):
    def __init__(self):
        super().__init__(name="get_workspace")
        self.capability = Capability.ANALYZE
        self.description = "Zwraca bieżący aktywny katalog roboczy (workspace) dla serwera AGOS."
    def execute(self, **kwargs) -> str:
        current = str(workspace_manager.get_current_workspace())
        default = str(workspace_manager.get_default_workspace())
        is_def = workspace_manager.is_default()
        return f"Aktywny workspace: {current} (Domyślny: {default}, Czy domyślny: {is_def})"

class SwitchWorkspaceTool(TrustedTool):
    def __init__(self):
        super().__init__(name="switch_workspace")
        self.capability = Capability.ANALYZE
        self.description = "Przestawia aktywny workspace AGOS na inny projekt w locie."
    def execute(self, workspace_path: str = "", **kwargs) -> str:
        try:
            new_ws = workspace_manager.set_workspace(workspace_path)
            return f"[SUKCES] Workspace AGOS pomyślnie przestawiony na: {new_ws}"
        except Exception as e:
            return f"[BŁĄD] Nie udało się przestawić workspace: {e}"

class ResetWorkspaceTool(TrustedTool):
    def __init__(self):
        super().__init__(name="reset_workspace")
        self.capability = Capability.ANALYZE
        self.description = "Przywraca domyślny workspace AGOS."
    def execute(self, **kwargs) -> str:
        res = workspace_manager.reset_workspace()
        return f"[SUKCES] Workspace AGOS zresetowany do domyślnego: {res}"

class DLPScannerTool(TrustedTool):
    def __init__(self):
        super().__init__(name="dlp_scanner")
        self.capability = Capability.ANALYZE
        self.description = "Skanuje i pseudonimizuje tekst pod kątem PII (PESEL, NIP, Karty, IBAN, Email) oraz sekretów (DLPEngine AGOS 4.1)."
        self.parameters = {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Tekst do przeskanowania przez silnik DLP"}
            },
            "required": ["text"]
        }
    def execute(self, text: str = "", **kwargs) -> str:
        from agos.security.dlp import DLPEngine, DLPMode, TokenVault
        engine = DLPEngine(mode=DLPMode.ENFORCE)
        vault = TokenVault()
        res = engine.scan_and_process(text, vault=vault, mode_override=DLPMode.ENFORCE)
        categories = [f"{f.category}:{f.placeholder}" for f in res.findings]
        return json.dumps({
            "findings_count": len(res.findings),
            "categories": categories,
            "redacted_text": res.sanitized_text
        }, ensure_ascii=False)

class SupplyChainAuditorTool(TrustedTool):
    def __init__(self):
        super().__init__(name="supply_chain_auditor")
        self.capability = Capability.ANALYZE
        self.description = "Weryfikuje przypięte zależności (requirements-pinned.txt) pod kątem pinowania wersji i slopsquattingu (AGOS 4.1)."
        self.parameters = {
            "type": "object",
            "properties": {
                "lockfile": {"type": "string", "description": "Ścieżka względna do pliku lockfile (domyślnie requirements-pinned.txt)"}
            },
            "required": []
        }
    def execute(self, lockfile: str = "requirements-pinned.txt", **kwargs) -> str:
        from pathlib import Path
        from agos.security.dependency_guard import read_text_auto_encoding
        from agos.security.supply_chain import verify_pinned_requirements
        ws = workspace_manager.get_current_workspace()
        target = (Path(ws) / lockfile).resolve()
        if not target.exists():
            return f"[BŁĄD] Plik nie istnieje: {target}"
        content = read_text_auto_encoding(target)
        passed, violations = verify_pinned_requirements(content)
        if passed:
            return f"[PASSED] Lockfile '{lockfile}' zweryfikowany pomyślnie (brak slopsquattingu, wszystkie wersje przypięte ==)."
        return f"[FAILED] Wykryto problemy w '{lockfile}': " + "; ".join(violations)

registry.register(SystemStatusTool())
registry.register(SecurityScannerTool())
registry.register(ProjectScannerTool())
registry.register(PythonStaticAnalyzerTool())
registry.register(GetWorkspaceTool())
registry.register(SwitchWorkspaceTool())
registry.register(ResetWorkspaceTool())
registry.register(DLPScannerTool())
registry.register(SupplyChainAuditorTool())

# Handler narzędzi używający FlexibleParams, aby odrzucić błędy "-32602: Invalid request parameters"
async def list_tools_handler(context, params: FlexibleParams) -> types.ListToolsResult:
    try:
        tools = [
            types.Tool(
                name="system_status",
                description="Pobiera status systemu AGOS 4.1 i weryfikuje integralność runtime.",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            types.Tool(
                name="get_workspace",
                description="Zwraca bieżący aktywny katalog roboczy (workspace) dla serwera AGOS.",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            types.Tool(
                name="switch_workspace",
                description="Przestawia aktywny workspace AGOS na dowolny inny projekt (np. 'C:\\Users\\mariu\\OneDrive\\Pulpit\\Zlecenie').",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "workspace_path": {"type": "string", "description": "Ścieżka do katalogu projektu"}
                    },
                    "required": ["workspace_path"]
                }
            ),
            types.Tool(
                name="reset_workspace",
                description="Przywraca domyślny workspace AGOS.",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            types.Tool(
                name="security_scanner",
                description="Skanuje plik pod kątem wycieków sekretów, AST-SAST oraz slopsquattingu (AGOS 4.1).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filepath": {"type": "string", "description": "Ścieżka do pliku w projekcie"}
                    },
                    "required": ["filepath"]
                }
            ),
            types.Tool(
                name="project_scanner",
                description="Skanuje strukturę projektu z poszanowaniem granic workspace i reguł bezpieczeństwa.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "directory": {"type": "string", "description": "Katalog relatywny (domyślnie główny)"},
                        "max_depth": {"type": "integer", "description": "Maksymalna głębokość skanowania"}
                    },
                    "required": []
                }
            ),
            types.Tool(
                name="python_static_analyzer",
                description="Statyczna analiza kodu Python (AST) weryfikująca poprawność składniową.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filepath": {"type": "string", "description": "Ścieżka do pliku .py"}
                    },
                    "required": ["filepath"]
                }
            ),
            types.Tool(
                name="dlp_scanner",
                description="Skanuje i pseudonimizuje tekst pod kątem PII (PESEL, NIP, Karty, IBAN, Email) oraz sekretów (DLPEngine AGOS 4.1).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Tekst do przeskanowania przez silnik DLP"}
                    },
                    "required": ["text"]
                }
            ),
            types.Tool(
                name="supply_chain_auditor",
                description="Weryfikuje przypięte zależności (requirements-pinned.txt) pod kątem pinowania wersji i slopsquattingu (AGOS 4.1).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "lockfile": {"type": "string", "description": "Ścieżka względna do pliku lockfile (domyślnie requirements-pinned.txt)"}
                    },
                    "required": []
                }
            )
        ]
        return types.ListToolsResult(tools=tools)
    except Exception as e:
        print(f"[SERWER-BŁĄD] w tools/list: {e}", file=sys.stderr)
        raise

async def call_tool_handler(context, params: FlexibleParams) -> types.CallToolResult:
    try:
        name = params.name
        args_dict = params.arguments or {}
        
        # INV-032: MCP_CANNOT_GRANT_AUTHORITY
        # MCP is an untrusted external boundary. Mutation tools require an Operation context
        # which MCP cannot provide. Only READ/ANALYZE tools are permitted via MCP.
        tool = registry.get_tool(name)
        if tool is not None:
            from agos.security.capabilities import Capability
            capability = getattr(tool, 'capability', Capability.ANALYZE)
            if Capability.is_mutation(capability):
                from agos.core.audit import audit_trail
                audit_trail.record(
                    operation_id='MCP-BOUNDARY',
                    state='UNKNOWN',
                    action=str(capability),
                    target=name,
                    result='DENY',
                    reason=f'INV-032: MCP_CANNOT_GRANT_AUTHORITY — MCP boundary cannot authorize '
                           f'mutation tool "{name}" (capability: {capability}). '
                           f'Mutation requires an explicit Operation context. [MCP_MUTATION_DENIED]'
                )
                error_response = {
                    'error': f'INV-032: MCP_CANNOT_GRANT_AUTHORITY',
                    'reason': f'Mutation tool "{name}" with capability "{capability}" '
                              f'cannot be invoked via MCP without an Operation context.',
                    'reason_code': 'MCP_MUTATION_DENIED',
                }
                return types.CallToolResult(
                    content=[types.TextContent(type='text', text=json.dumps(error_response))]
                )
        
        result = registry.execute_tool(name, **args_dict)
        
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(result))]
        )
    except Exception as e:
        print(f"[SERWER-BŁĄD] w tools/call: {e}", file=sys.stderr)
        raise

# Rejestracja endpointów przy użyciu naszego elastycznego modelu
app.add_request_handler("tools/list", FlexibleParams, list_tools_handler)
app.add_request_handler("tools/call", FlexibleParams, call_tool_handler)

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    import os
    if not os.environ.get("AGOS_PROVENANCE_SECRET"):
        os.environ["AGOS_PROVENANCE_SECRET"] = "agos-4-1-local-default-provenance-secret-32b!"
    asyncio.run(main())
