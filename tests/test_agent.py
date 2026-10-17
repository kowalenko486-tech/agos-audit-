import pytest
from agos.core.router import ToolRegistry
from agos.core.provenance import TrustedTool
from agos.core.agent import AgosAgent

PROVENANCE_SECRET = "test-provenance-secret-for-pytest-minimum-32-chars!"


@pytest.fixture(autouse=True)
def set_provenance_secret(monkeypatch):
    monkeypatch.setenv("AGOS_PROVENANCE_SECRET", PROVENANCE_SECRET)


# 1. Definicja zaufanego narzędzia
class FileSearchTool(TrustedTool):
    def __init__(self):
        super().__init__(name="search_files")
    
    def execute(self, query: str) -> str:
        if "dyrektywa" in query:
            return "Zasada główna: Twierdzenie != Dowód."
        return "Brak wyników."

# 2. Mock zachowania LLM (symulacja "mózgu" modelu)
def mock_llm_response(prompt: str) -> dict:
    if "dyrektywa" in prompt:
        return {
            "tool_call": {
                "name": "search_files",
                "kwargs": {"query": "dyrektywa"}
            },
            "claim": "Główna dyrektywa systemu zakłada, że samo twierdzenie nie wystarcza i nie jest dowodem."
        }
    return {}

def test_end_to_end_agent_loop():
    # SETUP: Budowa całego systemu "od zera"
    registry = ToolRegistry()
    registry.register(FileSearchTool())
    agent = AgosAgent(registry=registry, llm_mock=mock_llm_response)
    
    # AKCJA: Użytkownik zadaje pytanie do Agenta
    user_prompt = "Jak brzmi dyrektywa systemu?"
    verified_statement = agent.run(user_prompt)
    
    # WERYFIKACJA (EVIDENCE): Reguła Twierdzenie != Dowód zadziałała
    assert "nie jest dowodem" in verified_statement.claim
    assert len(verified_statement.evidences) == 1
    assert verified_statement.evidences[0].source == "search_files"
    assert verified_statement.evidences[0].raw_data == "Zasada główna: Twierdzenie != Dowód."
    assert verified_statement.evidences[0].provenance_hash is not None
