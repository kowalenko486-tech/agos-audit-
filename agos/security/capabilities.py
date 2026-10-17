"""AGOS 3.1 Tool Capabilities Definition."""
from enum import Enum

class Capability(str, Enum):
    READ = "READ"      # Non-mutating file read
    ANALYZE = "ANALYZE"  # Non-mutating analysis (e.g., security scan)
    WRITE = "WRITE"    # File content mutation
    DELETE = "DELETE"  # File deletion (irreversible)
    COMMIT = "COMMIT"  # Git commit (persists mutation to history)
    PUSH = "PUSH"      # Remote push (external effect, separated from COMMIT)
    DEPLOY = "DEPLOY"  # Deployment (external effect, highest risk)

    @classmethod
    def is_mutation(cls, capability: "Capability") -> bool:
        """Determines if the capability mutates filesystem or external systems."""
        return capability in (cls.WRITE, cls.DELETE, cls.COMMIT, cls.PUSH, cls.DEPLOY)

    def __str__(self) -> str:
        return self.value
