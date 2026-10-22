"""
AGOS 3.1/3.2 — Egress Data Loss Prevention (DLP) & Reversible Pseudonymization.

Zero-dependency, sub-millisecond DLP engine protecting prompts and tool outputs
before egress to external LLM APIs (OWASP LLM02: Sensitive Information Disclosure).

Features:
  1. Mathematical checksum validation (PESEL, NIP, IBAN mod-97, Credit Card Luhn)
     to eliminate false positives on ordinary numbers in source code.
  2. High-confidence regex detectors for emails, JWTs, PEM private keys, and cloud/API tokens.
  3. Base64 decode-and-scan defense against encoded exfiltration.
  4. Reversible pseudonymization via an in-memory per-operation TokenVault
     (de-pseudonymizes LLM responses locally without exposing raw PII to the LLM provider).
  5. Configurable operational modes via AGOS_DLP_MODE:
     - 'off'     : bypass scanning
     - 'warn'    : detect and log findings, do not modify payload (default for smooth operation)
     - 'enforce' : mask/pseudonymize all findings before LLM egress
     - 'block'   : fail-closed (raise DLPViolationError on any finding)
"""
import base64
import logging
import os
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("agos.security.dlp")


class DLPMode(str, Enum):
    OFF = "off"
    WARN = "warn"
    ENFORCE = "enforce"
    BLOCK = "block"

    @classmethod
    def from_env(cls) -> "DLPMode":
        raw = os.getenv("AGOS_DLP_MODE", "enforce").strip().lower()
        for mode in cls:
            if mode.value == raw:
                return mode
        logger.warning(f"[AGOS DLP] Unknown AGOS_DLP_MODE='{raw}', falling back to 'enforce' (fail-safe).")
        return cls.ENFORCE


class DLPViolationError(RuntimeError):
    """Raised when DLP is in BLOCK mode and sensitive data is detected on egress."""


@dataclass(frozen=True)
class DLPFinding:
    category: str
    placeholder: str
    start: int
    end: int


@dataclass
class DLPResult:
    original_text: str
    sanitized_text: str
    findings: List[DLPFinding] = field(default_factory=list)
    mode: DLPMode = DLPMode.WARN

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0


class TokenVault:
    """
    In-memory per-operation mapping between raw sensitive values and pseudonymized tokens.
    Never persisted to disk or sent to external APIs.
    """

    def __init__(self) -> None:
        self._value_to_token: Dict[Tuple[str, str], str] = {}
        self._token_to_value: Dict[str, str] = {}
        self._counters: Dict[str, int] = {}

    def get_or_create_token(self, category: str, raw_value: str) -> str:
        key = (category, raw_value)
        if key in self._value_to_token:
            return self._value_to_token[key]
        idx = self._counters.get(category, 0) + 1
        self._counters[category] = idx
        prefix = "SECRET" if category in ("API_KEY", "PRIVATE_KEY", "JWT") else "PII"
        token = f"[{prefix}:{category}_{idx}]"
        self._value_to_token[key] = token
        self._token_to_value[token] = raw_value
        return token

    def deanonymize(self, text: str) -> str:
        """Restores pseudonymized tokens back to their original values locally."""
        if not text or not self._token_to_value:
            return text
        result = text
        for token, raw_value in self._token_to_value.items():
            result = result.replace(token, raw_value)
        return result

    @property
    def size(self) -> int:
        return len(self._token_to_value)

    def tokens(self) -> list:
        """Public, value-free view: [(token, category)] — never exposes raw sensitive values."""
        return [(tok, tok.strip("[]").split(":", 1)[-1].rsplit("_", 1)[0]) for tok in self._token_to_value]


# ── Mathematical Checksum Validators ─────────────────────────────────────────

def is_valid_pesel(candidate: str) -> bool:
    """Validates an 11-digit Polish PESEL number (date sanity + modulo-10 weight checksum)."""
    if len(candidate) != 11 or not candidate.isdigit():
        return False
    month = int(candidate[2:4])
    day = int(candidate[4:6])
    # Valid month encodings across centuries: 01-12, 21-32, 41-52, 61-72, 81-92
    base_month = month % 20
    if not (1 <= base_month <= 12) or not (1 <= day <= 31):
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    checksum = sum(int(d) * w for d, w in zip(candidate[:10], weights)) % 10
    control = (10 - checksum) % 10
    return control == int(candidate[10])


def is_valid_nip(candidate: str) -> bool:
    """Validates a 10-digit Polish NIP tax identifier (modulo-11 weight checksum)."""
    digits = re.sub(r"[\s\-]", "", candidate)
    if len(digits) != 10 or not digits.isdigit() or len(set(digits)) == 1:
        return False
    weights = (6, 5, 7, 2, 3, 4, 5, 6, 7)
    checksum = sum(int(d) * w for d, w in zip(digits[:9], weights)) % 11
    if checksum == 10:
        return False
    return checksum == int(digits[9])


def is_valid_luhn(candidate: str) -> bool:
    """Validates a credit card number (13-19 digits) using the Luhn algorithm."""
    digits = re.sub(r"[\s\-]", "", candidate)
    if not (13 <= len(digits) <= 19) or not digits.isdigit() or len(set(digits)) == 1:
        return False
    # Major card network prefixes: 4 (Visa), 51-55/22-27 (Mastercard), 34/37 (Amex), 6 (Discover/Maestro)
    if not re.match(r"^(4|5[1-5]|2[2-7]|3[47]|6)", digits):
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def is_valid_iban(candidate: str) -> bool:
    """Validates an ISO 13616 IBAN using the modulo-97 algorithm."""
    cleaned = re.sub(r"\s+", "", candidate).upper()
    if not (15 <= len(cleaned) <= 34):
        return False
    if not re.match(r"^[A-Z]{2}[0-9]{2}[A-Z0-9]+$", cleaned):
        return False
    if cleaned.startswith("PL") and len(cleaned) != 28:
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    numeric_parts: List[str] = []
    for ch in rearranged:
        if ch.isdigit():
            numeric_parts.append(ch)
        else:
            numeric_parts.append(str(ord(ch) - 55))
    numeric_str = "".join(numeric_parts)
    return int(numeric_str) % 97 == 1


# ── DLP Scanner Engine ───────────────────────────────────────────────────────

class DLPEngine:
    """
    Zero-dependency DLP scanner and pseudonymizer for AGOS.
    """

    # High-confidence regex patterns (order matters: specific secrets before generic PII)
    _PATTERNS: List[Tuple[str, re.Pattern, Optional[callable]]] = [
        (
            "PRIVATE_KEY",
            re.compile(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
                r"(?:[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)?",
            ),
            None,
        ),
        (
            "API_KEY",
            re.compile(
                r"\b(?:"
                r"sk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{20,}"
                r"|AIza[0-9A-Za-z_\-]{35}"
                r"|AKIA[0-9A-Z]{16}"
                r"|gh[pousr]_[A-Za-z0-9_]{30,}"
                r"|xox[baprs]-[A-Za-z0-9\-]{10,}"
                r")\b"
            ),
            None,
        ),
        (
            "JWT",
            re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
            None,
        ),
        (
            "IBAN",
            re.compile(r"\b[A-Z]{2}\d{2}(?:\s?\d{4}){5,7}\b"),
            is_valid_iban,
        ),
        (
            "CARD",
            re.compile(r"\b(?:\d{4}[\s\-]?){3}\d{1,7}\b"),
            is_valid_luhn,
        ),
        (
            "PESEL",
            re.compile(r"\b\d{11}\b"),
            is_valid_pesel,
        ),
        (
            "NIP",
            re.compile(r"\b(?:\d{3}-\d{3}-\d{2}-\d{2}|\d{3}-\d{2}-\d{2}-\d{3}|\d{10})\b"),
            is_valid_nip,
        ),
        (
            "EMAIL",
            re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b"),
            None,
        ),
    ]

    _B64_CANDIDATE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")

    def __init__(self, mode: Optional[DLPMode] = None) -> None:
        self._explicit_mode = mode

    @property
    def mode(self) -> DLPMode:
        if self._explicit_mode is not None:
            return self._explicit_mode
        return DLPMode.from_env()

    def scan_and_process(
        self,
        text: str,
        vault: Optional[TokenVault] = None,
        mode_override: Optional[DLPMode] = None,
    ) -> DLPResult:
        """
        Scans `text` for PII and secrets and applies the configured DLP mode.
        """
        active_mode = mode_override if mode_override is not None else self.mode
        if not isinstance(text, str):
            text = str(text)

        if active_mode == DLPMode.OFF or not text:
            return DLPResult(original_text=text, sanitized_text=text, findings=[], mode=active_mode)

        normalized = unicodedata.normalize("NFC", text)
        active_vault = vault if vault is not None else TokenVault()

        # Collect non-overlapping matches across all detectors
        matches: List[Tuple[int, int, str, str]] = []  # (start, end, category, raw_val)
        occupied: List[Tuple[int, int]] = []

        def _overlaps(s: int, e: int) -> bool:
            return any(not (e <= os_ or s >= oe) for os_, oe in occupied)

        for category, pattern, validator in self._PATTERNS:
            for m in pattern.finditer(normalized):
                s, e = m.span()
                if _overlaps(s, e):
                    continue
                candidate = m.group(0)
                if validator is not None and not validator(candidate):
                    continue
                occupied.append((s, e))
                matches.append((s, e, category, candidate))

        # Base64 decode-and-scan for encoded PII/secrets
        for m in self._B64_CANDIDATE.finditer(normalized):
            s, e = m.span()
            if _overlaps(s, e):
                continue
            b64_str = m.group(0)
            try:
                padded = b64_str + "=" * ((4 - len(b64_str) % 4) % 4)
                decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
                if not decoded:
                    continue
                for category, pattern, validator in self._PATTERNS:
                    for sub_m in pattern.finditer(decoded):
                        sub_cand = sub_m.group(0)
                        if validator is None or validator(sub_cand):
                            occupied.append((s, e))
                            matches.append((s, e, f"B64_{category}", b64_str))
                            break
                    else:
                        continue
                    break
            except Exception:
                pass

        if not matches:
            return DLPResult(original_text=text, sanitized_text=text, findings=[], mode=active_mode)

        matches.sort(key=lambda item: item[0])
        findings: List[DLPFinding] = []
        out_parts: List[str] = []
        last_idx = 0

        for s, e, category, raw_val in matches:
            placeholder = active_vault.get_or_create_token(category, raw_val)
            findings.append(DLPFinding(category=category, placeholder=placeholder, start=s, end=e))
            out_parts.append(normalized[last_idx:s])
            out_parts.append(placeholder)
            last_idx = e
        out_parts.append(normalized[last_idx:])
        redacted_text = "".join(out_parts)

        categories_summary = ", ".join(f.category for f in findings)
        if active_mode == DLPMode.BLOCK:
            logger.error(f"[AGOS DLP] BLOCKED egress containing sensitive data: {categories_summary}")
            raise DLPViolationError(
                f"[DLP BLOCK] Wykryto dane wrażliwe przed wysyłką do LLM ({categories_summary}). "
                f"Operacja zablokowana (AGOS_DLP_MODE=block)."
            )

        if active_mode == DLPMode.WARN:
            logger.warning(
                f"[AGOS DLP] Wykryto {len(findings)} elementów wrażliwych ({categories_summary}) "
                f"w trybie WARN (dane nie zostały zmodyfikowane). Ustaw AGOS_DLP_MODE=enforce, aby maskować."
            )
            return DLPResult(
                original_text=text,
                sanitized_text=text,
                findings=findings,
                mode=active_mode,
            )

        # DLPMode.ENFORCE
        logger.warning(
            f"[AGOS DLP] Zamaskowano {len(findings)} elementów wrażliwych ({categories_summary}) przed wysyłką do LLM."
        )
        return DLPResult(
            original_text=text,
            sanitized_text=redacted_text,
            findings=findings,
            mode=active_mode,
        )


dlp_engine = DLPEngine()
