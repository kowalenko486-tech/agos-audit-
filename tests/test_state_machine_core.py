import pytest
from agos.core.state_machine import StateMachine, OperationState, StateTransitionError

def test_happy_path_strict_lifecycle():
    # Inicjalizacja domyślnie w READ_ONLY
    sm = StateMachine()
    assert sm.current_state == OperationState.READ_ONLY
    
    # Przejście przez wszystkie legalne stany
    sm.transition_to(OperationState.EVIDENCE)
    sm.transition_to(OperationState.PLAN)
    sm.transition_to(OperationState.AWAITING_APPROVAL)
    sm.transition_to(OperationState.APPROVED)
    sm.transition_to(OperationState.EXECUTING)
    sm.transition_to(OperationState.VERIFYING)
    
    # Przejście przez bramkę weryfikacyjną z flagą bezpieczeństwa
    sm.transition_to(OperationState.COMMIT_AUTHORIZED, verification_passed=True)
    sm.transition_to(OperationState.STOP)
    
    assert sm.current_state == OperationState.STOP

def test_fail_closed_on_illegal_transition():
    sm = StateMachine()
    # Atak: próba bezpośredniego wykonania kodu (omijając APPROVAL)
    with pytest.raises(StateTransitionError, match="Illegal state transition attempted"):
        sm.transition_to(OperationState.EXECUTING)
        
    # Sprawdzenie czy maszyna zatrzasnęła się w stanie ABORT (Fail-Closed)
    assert sm.current_state == OperationState.ABORT

def test_inv003_verify_fail_no_commit():
    sm = StateMachine(initial_state=OperationState.VERIFYING)
    
    # Atak: próba autoryzacji zapisu bez potwierdzenia weryfikacji (brak verification_passed=True)
    with pytest.raises(StateTransitionError, match="VERIFY_FAIL_NO_COMMIT"):
        sm.transition_to(OperationState.COMMIT_AUTHORIZED)
