"""AGOS 3.1 Provenance — HMAC-based evidence signing with env-sourced secret."""
import hmac
import hashlib
import os


def _load_system_secret() -> bytes:
    """
    MED-01 FIX: Secret is loaded from environment variable AGOS_PROVENANCE_SECRET.
    Fail-closed: if not set or too short, raises RuntimeError.
    Never hardcoded, never has a default fallback value.
    """
    raw = os.environ.get("AGOS_PROVENANCE_SECRET", "")
    if not raw:
        raise RuntimeError(
            "[AGOS SECURITY] AGOS_PROVENANCE_SECRET environment variable is not set. "
            "System cannot start without a provenance secret. "
            "Set this variable via your secret provider (e.g. Google Secret Manager, Vault, .env). "
            "[FAIL CLOSED]"
        )
    encoded = raw.encode("utf-8")
    if len(encoded) < 32:
        raise RuntimeError(
            "[AGOS SECURITY] AGOS_PROVENANCE_SECRET is too short (minimum 32 bytes required). "
            "[FAIL CLOSED]"
        )
    return encoded


def _get_system_secret() -> bytes:
    """Returns the system secret, loading it from environment. Raises on failure."""
    return _load_system_secret()


def validate_provenance_secret_at_startup() -> bool:
    """
    Eagerly validates the AGOS_PROVENANCE_SECRET at startup.
    Call this from application entry points (AgosAgent.__init__, ToolRegistry.__init__).
    Returns True if valid, raises RuntimeError if secret is missing or too short.
    """
    import os
    import logging
    logger = logging.getLogger('agos.core.provenance')
    secret = os.environ.get('AGOS_PROVENANCE_SECRET', '')
    if not secret:
        logger.critical(
            '[AGOS SECURITY] AGOS_PROVENANCE_SECRET is not set. '
            'Provenance signing is disabled. Set this env var to at least 32 bytes.'
        )
        raise RuntimeError(
            'AGOS_PROVENANCE_SECRET must be set to at least 32 characters. '
            'This is required for cryptographic provenance of tool executions.'
        )
    if len(secret.encode('utf-8')) < 32:
        raise RuntimeError(
            f'AGOS_PROVENANCE_SECRET is too short ({len(secret.encode())} bytes). '
            f'Minimum required: 32 bytes.'
        )
    logger.debug('[AGOS] Provenance secret validated at startup.')
    return True


def generate_provenance_hash(source: str, raw_data: str) -> str:
    secret = _get_system_secret()
    msg = f"{source}::{raw_data}".encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def verify_provenance_hash(source: str, raw_data: str, signature: str) -> bool:
    secret = _get_system_secret()
    msg = f"{source}::{raw_data}".encode("utf-8")
    expected = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


class TrustedTool:
    def __init__(self, name: str):
        self.name = name

    def execute(self, **kwargs) -> str:
        raise NotImplementedError("Narzędzie musi implementować metodę execute.")

    def run_and_sign(self, **kwargs) -> dict:
        # Narzędzie wykonuje logikę i samo kryptograficznie stempluje wynik
        raw_data = str(self.execute(**kwargs))
        signature = generate_provenance_hash(self.name, raw_data)
        return {
            "source": self.name,
            "raw_data": raw_data,
            "provenance_hash": signature,
        }
