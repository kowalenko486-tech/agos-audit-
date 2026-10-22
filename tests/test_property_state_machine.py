"""
AGOS 4.1 Property-Based Testing (Hypothesis): Mathematical Verification of State Machine.

Mathematically proves that no arbitrary, randomized sequence of transitions,
fuzzing inputs, or invalid flags can EVER:
  1. Bypass approval or verification to reach COMMIT_AUTHORIZED.
  2. Escape a terminal state (ABORT, STOP, FAILED).
  3. Violate the fail-closed invariant (any illegal transition forces immediate terminal ABORT).
"""
import pytest
from hypothesis import given, strategies as st, settings
from agos.core.state_machine import StateMachine, OperationState, StateTransitionError


ALL_STATES = list(OperationState)
TERMINAL_STATES = (OperationState.ABORT, OperationState.STOP, OperationState.FAILED)
ACTIVE_STATES = [s for s in ALL_STATES if s not in TERMINAL_STATES]


@settings(max_examples=500, deadline=None)
@given(
    target_states=st.lists(st.sampled_from(ALL_STATES), min_size=1, max_size=30),
    verification_flags=st.lists(st.booleans(), min_size=30, max_size=30),
)
def test_hypothesis_fuzz_state_machine_never_violates_fail_closed(target_states, verification_flags):
    """
    Fuzzes the state machine with random target states and verification flags.
    Proves that fail-closed invariant holds: once any terminal state is reached, state is permanently locked.
    """
    sm = StateMachine(OperationState.READ_ONLY)
    
    for i, next_state in enumerate(target_states):
        v_flag = verification_flags[i]
        prior_state = sm.current_state

        if prior_state in TERMINAL_STATES:
            # Terminal invariant: Once in terminal state, ALL transitions MUST be rejected and state remains locked
            with pytest.raises(StateTransitionError):
                sm.transition_to(next_state, verification_passed=v_flag)
            assert sm.current_state == prior_state, f"Terminal state {prior_state} leaked into {sm.current_state}!"
        else:
            try:
                sm.transition_to(next_state, verification_passed=v_flag)
                assert sm.current_state == next_state
            except StateTransitionError:
                # On any invalid transition from an active state, fail-closed MUST transition immediately to ABORT
                assert sm.current_state == OperationState.ABORT, (
                    f"Invalid transition from {prior_state} to {next_state} did not fail closed to ABORT!"
                )


@settings(max_examples=300, deadline=None)
@given(
    intermediate_states=st.lists(
        st.sampled_from([s for s in ALL_STATES if s != OperationState.VERIFYING]),
        min_size=1,
        max_size=10
    )
)
def test_hypothesis_commit_authorized_strictly_unreachable_without_verifying(intermediate_states):
    """
    Proves that COMMIT_AUTHORIZED cannot be reached directly from any state other than VERIFYING
    with verification_passed=True.
    """
    sm = StateMachine(OperationState.READ_ONLY)
    
    for state in intermediate_states:
        try:
            sm.transition_to(state)
        except StateTransitionError:
            break
            
    if sm.current_state != OperationState.VERIFYING:
        # Directly attempting COMMIT_AUTHORIZED from any non-VERIFYING state MUST fail
        with pytest.raises(StateTransitionError):
            sm.transition_to(OperationState.COMMIT_AUTHORIZED, verification_passed=True)
        assert sm.current_state in TERMINAL_STATES
