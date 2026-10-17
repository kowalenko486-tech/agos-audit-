import pytest

def test_inv_capability_write_is_mutation():
    from agos.security.capabilities import Capability
    assert Capability.is_mutation(Capability.WRITE) is True
    assert Capability.is_mutation(Capability.DELETE) is True
    assert Capability.is_mutation(Capability.COMMIT) is True
    assert Capability.is_mutation(Capability.PUSH) is True
    assert Capability.is_mutation(Capability.DEPLOY) is True
    assert Capability.is_mutation(Capability.READ) is False
    assert Capability.is_mutation(Capability.ANALYZE) is False

def test_inv_deploy_strictly_denied(tmp_path):
    from agos.core.policy import PolicyEngine, PolicyDecision
    from agos.security.capabilities import Capability
    engine = PolicyEngine()
    res = engine.authorize(Capability.DEPLOY, operation=None)
    assert res.decision == PolicyDecision.DENY

def test_inv_delete_requires_operation():
    from agos.core.policy import PolicyEngine, PolicyDecision
    from agos.security.capabilities import Capability
    engine = PolicyEngine()
    res = engine.authorize(Capability.DELETE, operation=None)
    assert res.decision == PolicyDecision.DENY
