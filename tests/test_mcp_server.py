import asyncio
import json
import pytest
from agos.core.mcp_server import call_tool_handler, list_tools_handler, FlexibleParams, registry
from agos.core.provenance import TrustedTool
from agos.security.capabilities import Capability


def test_mcp_mutation_tool_denied():
    class FakeMutationTool(TrustedTool):
        def __init__(self):
            super().__init__(name='fake_write')
            self.capability = Capability.WRITE
        def execute(self, **kwargs):
            return 'should not reach here'

    registry.register(FakeMutationTool())

    params = FlexibleParams(name='fake_write', arguments={})

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(
        call_tool_handler(None, params)
    )
    content = json.loads(result.content[0].text)
    assert 'MCP_MUTATION_DENIED' in content.get('reason_code', '') or 'INV-032' in str(content)


def test_mcp_agos_4_1_system_status_and_dlp_tools():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # 1. Verify tools list includes new AGOS 4.1 tools
    tools_res = loop.run_until_complete(list_tools_handler(None, FlexibleParams()))
    tool_names = {t.name for t in tools_res.tools}
    assert "system_status" in tool_names
    assert "dlp_scanner" in tool_names
    assert "supply_chain_auditor" in tool_names

    # 2. Verify system_status reports AGOS 4.1
    status_res = loop.run_until_complete(
        call_tool_handler(None, FlexibleParams(name="system_status", arguments={}))
    )
    status_payload = json.loads(status_res.content[0].text)
    assert "AGOS 4.1" in status_payload["raw_data"]

    # 3. Verify dlp_scanner pseudonimizes PESEL over MCP
    dlp_res = loop.run_until_complete(
        call_tool_handler(
            None,
            FlexibleParams(name="dlp_scanner", arguments={"text": "PESEL klienta: 44051401458"}),
        )
    )
    dlp_payload = json.loads(dlp_res.content[0].text)
    dlp_data = json.loads(dlp_payload["raw_data"])
    assert dlp_data["findings_count"] >= 1
    assert "44051401458" not in dlp_data["redacted_text"]
    assert "[PII:PESEL_1]" in dlp_data["redacted_text"]

    # 4. Verify supply_chain_auditor passes on repository lockfile
    sc_res = loop.run_until_complete(
        call_tool_handler(
            None,
            FlexibleParams(name="supply_chain_auditor", arguments={"lockfile": "requirements-pinned.txt"}),
        )
    )
    sc_payload = json.loads(sc_res.content[0].text)
    assert "[PASSED]" in sc_payload["raw_data"]
