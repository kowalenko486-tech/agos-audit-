import pytest
from agos.core.router import ToolRegistry
from agos.core.provenance import TrustedTool
from agos.core.models import Evidence, VerifiedStatement

PROVENANCE_SECRET = "test-provenance-secret-for-pytest-minimum-32-chars!"


@pytest.fixture(autouse=True)
def set_provenance_secret(monkeypatch):
    monkeypatch.setenv("AGOS_PROVENANCE_SECRET", PROVENANCE_SECRET)



# Deklaracja bezpiecznego narzędzia testowego
class CalculatorTool(TrustedTool):
    def __init__(self):
        super().__init__(name="calculator")
    
    def execute(self, expression: str) -> str:
        if expression == "2+2":
            return "4"
        elif expression == "error":
            raise ValueError("Symulowany błąd dzielenia przez zero")
        return "Nieznane wyrażenie"

def test_registry_successful_execution_and_verification():
    registry = ToolRegistry()
    registry.register(CalculatorTool())
    
    # KROK 1: Orkiestrator odbiera intencję od LLM
    llm_tool_call = {"name": "calculator", "kwargs": {"expression": "2+2"}}
    
    # KROK 2: Router wykonuje narzędzie
    result = registry.execute_tool(llm_tool_call["name"], **llm_tool_call["kwargs"])
    
    # Weryfikacja, że narzędzie zwróciło poprawny pakiet dowodowy
    assert "error" not in result
    assert result["raw_data"] == "4"
    assert "provenance_hash" in result
    
    # KROK 3: LLM formułuje twierdzenie z dołączonym fizycznym dowodem
    statement = VerifiedStatement(
        claim="Wynik dodawania 2 i 2 to 4.",
        evidences=[Evidence(**result)]
    )
    assert statement.claim == "Wynik dodawania 2 i 2 to 4."

def test_registry_tool_not_found():
    registry = ToolRegistry()
    result = registry.execute_tool("nieistniejace_narzedzie")
    
    assert "error" in result
    assert "nie jest zarejestrowane" in result["error"]

def test_registry_tool_internal_error_handling():
    registry = ToolRegistry()
    registry.register(CalculatorTool())
    
    # Symulacja błędu wewnątrz narzędzia
    result = registry.execute_tool("calculator", expression="error")
    
    assert "error" in result
    assert "Symulowany błąd" in result["error"]
