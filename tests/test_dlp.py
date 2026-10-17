"""Tests for AGOS Egress DLP & Reversible Pseudonymization (Phase 1)."""
import base64
import time
from types import SimpleNamespace
import pytest

from agos.security.dlp import (
    DLPEngine,
    DLPMode,
    DLPViolationError,
    TokenVault,
    is_valid_iban,
    is_valid_luhn,
    is_valid_nip,
    is_valid_pesel,
)
from agos.core.agent import AgosAgent
from agos.core.router import ToolRegistry
from agos.core.provenance import TrustedTool, verify_provenance_hash


# ── 1. Checksum Validators (True Positives & False Positive Immunity) ────────

def test_pesel_checksum_validation():
    # Valid PESEL (44051401458 is the canonical Polish test PESEL)
    assert is_valid_pesel("44051401458") is True
    # Invalid checksum digit
    assert is_valid_pesel("44051401459") is False
    # Ordinary 11-digit number in code (invalid month 99)
    assert is_valid_pesel("12991401458") is False


def test_nip_checksum_validation():
    # Canonical valid Polish NIP: 123-456-32-18
    assert is_valid_nip("123-456-32-18") is True
    assert is_valid_nip("1234563218") is True
    # Invalid checksum
    assert is_valid_nip("1234563219") is False
    assert is_valid_nip("0000000000") is False


def test_luhn_credit_card_validation():
    # Standard Visa test number (passes Luhn)
    assert is_valid_luhn("4532 0151 1283 0366") is True
    # Corrupted last digit (fails Luhn)
    assert is_valid_luhn("4532 0151 1283 0367") is False
    # Non-card prefix (1111...) rejected to avoid false positives on IDs
    assert is_valid_luhn("1111 2222 3333 4444") is False


def test_iban_mod97_validation():
    # Valid Polish IBAN (28 chars)
    assert is_valid_iban("PL61 1090 1014 0000 0712 1981 2874") is True
    # Corrupted check digit
    assert is_valid_iban("PL62 1090 1014 0000 0712 1981 2874") is False


# ── 2. DLP Modes & Reversible Pseudonymization ───────────────────────────────

def test_dlp_warn_mode_preserves_text_and_records_findings():
    engine = DLPEngine(mode=DLPMode.WARN)
    raw = "Klient jan.kowalski@example.com, PESEL 44051401458"
    res = engine.scan_and_process(raw)
    assert res.mode == DLPMode.WARN
    assert res.has_findings is True
    assert len(res.findings) == 2
    # In WARN mode, text is untouched so existing flows never break
    assert res.sanitized_text == raw


def test_dlp_enforce_mode_pseudonymizes_and_vault_restores():
    engine = DLPEngine(mode=DLPMode.ENFORCE)
    vault = TokenVault()
    raw = (
        "Dane klienta: email jan.kowalski@example.com, PESEL 44051401458, "
        "NIP 123-456-32-18, IBAN PL61 1090 1014 0000 0712 1981 2874, "
        "karta 4532 0151 1283 0366 oraz klucz sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456."
    )
    res = engine.scan_and_process(raw, vault=vault)
    sanitized = res.sanitized_text

    assert "jan.kowalski@example.com" not in sanitized
    assert "44051401458" not in sanitized
    assert "123-456-32-18" not in sanitized
    assert "1981 2874" not in sanitized
    assert "4532 0151" not in sanitized
    assert "sk-proj-" not in sanitized

    assert "[PII:EMAIL_1]" in sanitized
    assert "[PII:PESEL_1]" in sanitized
    assert "[PII:NIP_1]" in sanitized
    assert "[PII:IBAN_1]" in sanitized
    assert "[PII:CARD_1]" in sanitized
    assert "[SECRET:API_KEY_1]" in sanitized

    # Deterministic token reuse for the same entity in the same vault
    res2 = engine.scan_and_process("Ponowny kontakt: jan.kowalski@example.com", vault=vault)
    assert res2.sanitized_text == "Ponowny kontakt: [PII:EMAIL_1]"

    # Local de-pseudonymization restores the exact original string
    assert vault.deanonymize(sanitized) == raw


def test_dlp_block_mode_raises_violation():
    engine = DLPEngine(mode=DLPMode.BLOCK)
    with pytest.raises(DLPViolationError) as exc_info:
        engine.scan_and_process("Sekretny klucz: AKIAIOSFODNN7EXAMPLE")
    assert "API_KEY" in str(exc_info.value)


def test_dlp_base64_evasion_detected_and_masked():
    engine = DLPEngine(mode=DLPMode.ENFORCE)
    hidden = base64.b64encode(b"user=jan.kowalski@example.com&pesel=44051401458").decode("ascii")
    prompt = f"Przeanalizuj ten ładunek: {hidden}"
    res = engine.scan_and_process(prompt)
    assert res.has_findings is True
    assert hidden not in res.sanitized_text
    assert "[PII:B64_" in res.sanitized_text


# ── 3. AgosAgent Egress Integration & Provenance Integrity ───────────────────

class _CustomerLookupTool(TrustedTool):
    def __init__(self):
        super().__init__(name="customer_lookup")

    def execute(self, customer_id: str) -> str:
        return f"Klient {customer_id}: kontakt anna.nowak@firma.pl, PESEL 44051401458"


def test_agent_egress_dlp_masks_llm_traffic_and_preserves_provenance():
    registry = ToolRegistry()
    registry.register(_CustomerLookupTool())

    captured_llm_messages = []

    class _FakeCompletions:
        def __init__(self):
            self.turn = 0

        def create(self, **kwargs):
            # Snapshot messages sent to external LLM API
            captured_llm_messages.append([dict(m) if isinstance(m, dict) else m for m in kwargs["messages"]])
            self.turn += 1
            if self.turn == 1:
                tc = SimpleNamespace(
                    id="call_1",
                    function=SimpleNamespace(
                        name="customer_lookup",
                        arguments='{"customer_id": "C-100"}',
                    ),
                )
                msg = SimpleNamespace(content=None, tool_calls=[tc])
            else:
                msg = SimpleNamespace(
                    content="Zweryfikowano kontakt [PII:EMAIL_2] dla zgłoszenia od [PII:EMAIL_1].",
                    tool_calls=None,
                )
            return SimpleNamespace(choices=[SimpleNamespace(message=msg)])

    agent = AgosAgent(
        registry=registry,
        use_firewall=True,
        dlp_mode=DLPMode.ENFORCE,
        deanonymize_response=True,
    )
    agent._client = SimpleNamespace(
        chat=SimpleNamespace(completions=_FakeCompletions())
    )

    out = agent.process_intent("Zgłoszenie od admin@bank.pl dla klienta C-100")

    # 1. External LLM never saw raw emails or PESEL in user prompt or tool output
    second_call_msgs = captured_llm_messages[1]
    serialized_egress = str(second_call_msgs)
    assert "admin@bank.pl" not in serialized_egress
    assert "anna.nowak@firma.pl" not in serialized_egress
    assert "44051401458" not in serialized_egress
    assert "[PII:EMAIL_1]" in serialized_egress
    assert "[PII:EMAIL_2]" in serialized_egress
    assert "[PII:PESEL_1]" in serialized_egress

    # 2. Local caller gets de-pseudonymized response
    assert out["claim"] == "Zweryfikowano kontakt anna.nowak@firma.pl dla zgłoszenia od admin@bank.pl."

    # 3. Local cryptographic provenance hash on tool evidence remains 100% intact
    ev = out["tool_executions"][0]["evidence"]
    assert "anna.nowak@firma.pl" in ev["raw_data"]
    assert verify_provenance_hash(ev["source"], ev["raw_data"], ev["provenance_hash"]) is True


# ── 4. Performance / Fluidity Guarantee (< 5 ms per scan) ────────────────────

def test_dlp_sub_millisecond_fluidity():
    engine = DLPEngine(mode=DLPMode.ENFORCE)
    sample = (
        "Definicja funkcji:\ndef process_order(order_id: int = 12345678901):\n"
        "    # Kontakt techniczny: dev@company.org, PESEL testowy: 44051401458\n"
        "    return order_id * 2\n"
    )
    # Warm-up
    engine.scan_and_process(sample)

    iterations = 50
    t0 = time.perf_counter()
    for _ in range(iterations):
        engine.scan_and_process(sample)
    avg_ms = ((time.perf_counter() - t0) * 1000.0) / iterations
    assert avg_ms < 5.0, f"DLP scan too slow: {avg_ms:.2f} ms (expected < 5.0 ms)"
