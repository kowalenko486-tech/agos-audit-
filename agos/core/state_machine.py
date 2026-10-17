"""AGOS 3.1 State Machine - Strict Lifecycle Transitions and Invariant Enforcement."""
from enum import Enum
from typing import Set, Dict, Optional

class OperationState(str, Enum):
    READ_ONLY = "READ_ONLY"
    EVIDENCE = "EVIDENCE"
    PLAN = "PLAN"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMMIT_AUTHORIZED = "COMMIT_AUTHORIZED"
    STOP = "STOP"
    ABORT = "ABORT"
    FAILED = "FAILED"  # Terminal failure state

    def __str__(self) -> str:
        return self.value

class StateTransitionError(RuntimeError):
    """Raised when an illegal state transition is attempted."""
    pass

class StateMachine:
    """
    Enforces the AGOS Core lifecycle:
    READ_ONLY -> EVIDENCE -> PLAN -> AWAITING_APPROVAL -> APPROVED ->
    EXECUTING -> VERIFYING -> COMMIT_AUTHORIZED -> STOP.

    Any security failure transitions immediately to ABORT.
    """

    ALLOWED_TRANSITIONS: Dict[OperationState, Set[OperationState]] = {
        OperationState.READ_ONLY: {OperationState.EVIDENCE, OperationState.ABORT, OperationState.FAILED},
        OperationState.EVIDENCE: {OperationState.PLAN, OperationState.READ_ONLY, OperationState.ABORT, OperationState.FAILED},
        OperationState.PLAN: {OperationState.AWAITING_APPROVAL, OperationState.EVIDENCE, OperationState.ABORT, OperationState.FAILED},
        OperationState.AWAITING_APPROVAL: {OperationState.APPROVED, OperationState.PLAN, OperationState.ABORT, OperationState.FAILED},
        OperationState.APPROVED: {OperationState.EXECUTING, OperationState.ABORT, OperationState.FAILED},
        OperationState.EXECUTING: {OperationState.VERIFYING, OperationState.ABORT, OperationState.FAILED},
        OperationState.VERIFYING: {OperationState.COMMIT_AUTHORIZED, OperationState.STOP, OperationState.ABORT, OperationState.FAILED},
        OperationState.COMMIT_AUTHORIZED: {OperationState.STOP, OperationState.ABORT, OperationState.FAILED},
        OperationState.STOP: set(),
        OperationState.ABORT: set(),
        OperationState.FAILED: set(),
    }

    def __init__(self, initial_state: OperationState = OperationState.READ_ONLY):
        self._current_state = initial_state
        self._history = [initial_state]

    @property
    def current_state(self) -> OperationState:
        return self._current_state

    @property
    def history(self) -> list:
        return list(self._history)

    def transition_to(self, new_state: OperationState, reason: str = "", verification_passed: Optional[bool] = None) -> OperationState:
        """
        Attempts a transition to new_state.
        If transition is forbidden, transitions to ABORT and raises StateTransitionError.

        SECURITY NOTE on ordering:
        1. Terminal state check first (STOP/ABORT/FAILED cannot transition at all).
        2. ALLOWED_TRANSITIONS check second (illegal transitions go to ABORT immediately).
        3. COMMIT_AUTHORIZED verification_passed gate last (only fires when transition IS allowed).
           This ordering ensures that EXECUTING->COMMIT_AUTHORIZED (illegal) still produces
           ABORT state, while VERIFYING->COMMIT_AUTHORIZED (legal) enforces verification_passed.
        """
        if self._current_state in (OperationState.STOP, OperationState.ABORT, OperationState.FAILED):
            raise StateTransitionError(
                f"Terminal state reached: cannot transition from {self._current_state} to {new_state}."
            )

        allowed = self.ALLOWED_TRANSITIONS.get(self._current_state, set())
        if new_state not in allowed:
            prev = self._current_state
            # Fail closed: transition immediately to ABORT
            self._current_state = OperationState.ABORT
            self._history.append(OperationState.ABORT)
            raise StateTransitionError(
                f"Illegal state transition attempted: {prev} -> {new_state}. Reason: {reason or 'Forbidden by AGOS protocol'}. State transitioned to ABORT."
            )

        # INV-003 / VERIFY_FAIL_NO_COMMIT:
        # COMMIT_AUTHORIZED requires explicit verification_passed=True.
        # This check fires AFTER the transition-allowed check so that illegal transitions
        # (e.g. EXECUTING -> COMMIT_AUTHORIZED) still produce ABORT state first.
        if new_state == OperationState.COMMIT_AUTHORIZED:
            if verification_passed is not True:
                raise StateTransitionError(
                    f'Transition to COMMIT_AUTHORIZED requires verification_passed=True. '
                    f'Received: {verification_passed}. '
                    f'[VERIFY_FAIL_NO_COMMIT]'
                )

        self._current_state = new_state
        self._history.append(new_state)
        return self._current_state

    def abort(self, reason: str = "") -> OperationState:
        """Unconditionally aborts the state machine."""
        if self._current_state != OperationState.ABORT:
            self._current_state = OperationState.ABORT
            self._history.append(OperationState.ABORT)
        return self._current_state
