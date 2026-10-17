#!/usr/bin/env python3
"""
AGOS 4.1 Standalone External Validation & Red-Team Test Runner.
Zero-Trust Verification Engine for CI/CD, Docker, VPS, and Remote Machines.

Usage:
    python run_validation.py             # Runs dynamic probes + core red-team suites
    python run_validation.py --probe     # Runs only the 14 dynamic security probes
    python run_validation.py --all       # Runs dynamic probes + ALL pytest suites
"""
import sys
import os
import json
import time
import argparse
from pathlib import Path

# Ensure AGOS_PROVENANCE_SECRET is present before importing AGOS modules
if not os.environ.get("AGOS_PROVENANCE_SECRET"):
    os.environ["AGOS_PROVENANCE_SECRET"] = "agos-4-1-external-validation-secret-minimum-32b!"

# Add validator root to sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# ANSI Color helpers
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def log_step(name, passed, detail=""):
    tag = f"{GREEN}[PASS]{RESET}" if passed else f"{RED}[FAIL]{RESET}"
    det = f" ({detail})" if detail else ""
    print(f"  {tag} {name}{det}")


def run_dynamic_probes():
    """Executes the 14 in-memory dynamic red-team probes against AGOS security engines."""
    print(f"\n{BOLD}{CYAN}=== ETAP 1: DYNAMICZNE SONDY ADWERSARYJNE RED-TEAM (IN-MEMORY) ==={RESET}")
    probe_results = []

    from agos.security.dlp import (
        DLPEngine, DLPMode, TokenVault,
        is_valid_pesel, is_valid_nip, is_valid_luhn, is_valid_iban
    )
    from agos.security.llm_output_guard import LLMOutputGuard, OutputGuardMode
    from agos.tools.security import scan_python_ast_sast
    from agos.security.dependency_guard import DependencyGuard
    from agos.security.sensitive_files import is_sensitive_path
    from agos.security.paths import resolve_and_validate_path, SecurityPathError
    from agos.core.policy import PolicyEngine, PolicyDecision
    from agos.core.scope import ExecutionScope
    from agos.tools.modifier import FileModifierTool

    # 1. Egress DLP - PESEL Checksum
    p_ok = is_valid_pesel("44051401458") and not is_valid_pesel("44051401459")
    log_step("DLP: Weryfikacja sumy kontrolnej i daty PESEL", p_ok)
    probe_results.append(("DLP_PESEL_Checksum", p_ok))

    # 2. Egress DLP - NIP Checksum
    n_ok = is_valid_nip("123-456-32-18") and not is_valid_nip("123-456-32-19")
    log_step("DLP: Weryfikacja sumy kontrolnej wag NIP (modulo-11)", n_ok)
    probe_results.append(("DLP_NIP_Checksum", n_ok))

    # 3. Egress DLP - Luhn Credit Card
    c_ok = is_valid_luhn("4532 0151 1283 0366") and not is_valid_luhn("4532 0151 1283 0367")
    log_step("DLP: Weryfikacja kart płatniczych algorytmem Luhna", c_ok)
    probe_results.append(("DLP_Luhn_Card", c_ok))

    # 4. Egress DLP - IBAN ISO 7064
    iban_ok = is_valid_iban("PL61109010140000071219812874") and not is_valid_iban("PL61109010140000071219812875")
    log_step("DLP: Weryfikacja rachunku bankowego IBAN (ISO mod-97)", iban_ok)
    probe_results.append(("DLP_IBAN_Checksum", iban_ok))

    # 5. Egress DLP - Pseudonimizacja & Reversibility w TokenVault
    dlp = DLPEngine(mode=DLPMode.ENFORCE)
    vault = TokenVault()
    raw_payload = "Klient: jan@firma.pl, PESEL: 44051401458, NIP: 123-456-32-18, API: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
    proc = dlp.scan_and_process(raw_payload, vault=vault)
    san = proc.sanitized_text
    masked = ("44051401458" not in san) and ("[PII:PESEL_1]" in san) and ("[SECRET:API_KEY_1]" in san)
    restored = vault.deanonymize(san)
    vault_ok = masked and (restored == raw_payload)
    log_step("DLP: Odwracalna pseudonimizacja w TokenVault (Zero Egress Leak)", vault_ok)
    probe_results.append(("DLP_Pseudonymization_Vault", vault_ok))

    # 6. Egress DLP - Base64 Evasion Intercept
    import base64
    b64_payload = "Wiadomosc ukryta: " + base64.b64encode(b"dane: pesel=44051401458&tajne=1").decode("ascii")
    proc_b64 = dlp.scan_and_process(b64_payload, vault=vault)
    b64_ok = "[PII:B64_" in proc_b64.sanitized_text
    log_step("DLP: Przechwytywanie prób obejścia przez Base64 Decode-and-Scan", b64_ok)
    probe_results.append(("DLP_Base64_Evasion_Intercept", b64_ok))

    # 7. LLMOutputGuard - Ochrona klucza systemowego AGOS_PROVENANCE_SECRET
    guard = LLMOutputGuard(mode=OutputGuardMode.ENFORCE)
    secret_text = f"Próba wycieku sekretu: {os.environ['AGOS_PROVENANCE_SECRET']}"
    guard_res, _ = guard.sanitize_output(secret_text)
    guard_ok = (os.environ['AGOS_PROVENANCE_SECRET'] not in guard_res) and ("[REDACTED_SYSTEM_SECRET]" in guard_res)
    log_step("LLM Guard: Bezwzględne wycięcie AGOS_PROVENANCE_SECRET", guard_ok)
    probe_results.append(("Provenance_Secret_Redaction", guard_ok))

    # 8. AST-SAST - Blokada niebezpiecznych funkcji Pythona
    malicious_code = """
import os, subprocess, pickle, yaml
eval('1+1')
exec('import sys')
subprocess.run('ls', shell=True)
pickle.loads(b'cos')
yaml.load('foo: bar')
"""
    findings = scan_python_ast_sast(malicious_code)
    text_findings = " ".join(findings)
    sast_ok = (
        ("eval" in text_findings) and
        ("exec" in text_findings) and
        ("shell=True" in text_findings) and
        ("pickle" in text_findings) and
        ("yaml.load" in text_findings)
    )
    log_step("AST-SAST: Wykrycie eval, exec, subprocess(shell=True), pickle, yaml.load", sast_ok)
    probe_results.append(("AST_SAST_Vulnerabilities", sast_ok))

    # 9. DependencyGuard - Typosquatting (Damerau-Levenshtein)
    dep_guard = DependencyGuard()
    typo_findings = dep_guard.scan_requirements_text("reqeusts==2.31.0\nfastpai==0.110.0\ncrytpography==42.0.0\n")
    typo_ok = any(f.category == "TYPOSQUATTING" for f in typo_findings)
    log_step("Supply Chain: Wykrywanie Typosquattingu bibliotek", typo_ok)
    probe_results.append(("SupplyChain_Typosquatting", typo_ok))

    # 10. DependencyGuard - Anti-Slopsquatting (AI Hallucinated Packages)
    slop_findings = dep_guard.scan_requirements_text("chatgpt-helper==1.0.0\npy-openai-utils==0.2.0\nauto-security-ai==0.1.0\n")
    slop_ok = any(f.category == "SLOPSQUATTING_PATTERN" for f in slop_findings)
    log_step("Supply Chain: Wykrywanie halucynacji AI (Anti-Slopsquatting)", slop_ok)
    probe_results.append(("SupplyChain_Slopsquatting", slop_ok))

    # 11. Ochrona plików wrażliwych
    sens_ok = (
        is_sensitive_path(".env") and
        is_sensitive_path(".env.prod") and
        is_sensitive_path("id_rsa") and
        is_sensitive_path(".ssh/config") and
        is_sensitive_path("secret.key") and
        not is_sensitive_path("main.py") and
        not is_sensitive_path("app/utils.py")
    )
    log_step("Scope Guard: Ochrona plików wrażliwych (.env, SSH, .key)", sens_ok)
    probe_results.append(("Sensitive_File_Enforcement", sens_ok))

    # 12. Workspace Escape & UNC Paths
    unc_denied = False
    try:
        resolve_and_validate_path(str(BASE_DIR), r"\\malicious\share\exploit.py")
    except SecurityPathError:
        unc_denied = True
    traversal_denied = False
    try:
        resolve_and_validate_path(str(BASE_DIR), "../../../../etc/shadow")
    except SecurityPathError:
        traversal_denied = True
    log_step("Scope Guard: Blokada ucieczki z katalogu i ścieżek sieciowych UNC", unc_denied and traversal_denied)
    probe_results.append(("Workspace_Escape_Defense", unc_denied and traversal_denied))

    # 13. Policy Engine - Blokada bezpośredniego użycia narzędzi (Direct Tool Mutation Bypass)
    mod_tool = FileModifierTool(workspace_root=str(BASE_DIR))
    bypass_res = mod_tool.execute(filepath="test.txt", content="x", operation=None)
    direct_bypass_ok = "[POLICY DENIED]" in bypass_res and ("Direct tool bypass" in bypass_res or "INV-023" in bypass_res)
    log_step("Policy Engine: Blokada mutacji bez aktywnej operacji (INV-023 Direct Bypass)", direct_bypass_ok)
    probe_results.append(("Direct_Tool_Bypass_Blocked", direct_bypass_ok))

    # 14. Policy Engine - Zasada Fail-Closed przy błędach
    policy = PolicyEngine(fail_closed=True)
    exc_res = policy.authorize(capability=None, operation=None)
    fail_closed_ok = (exc_res.decision == PolicyDecision.DENY)
    log_step("Policy Engine: Zasada Fail-Closed przy wyjątkach wejściowych", fail_closed_ok)
    probe_results.append(("Policy_Exception_Fail_Closed", fail_closed_ok))

    return probe_results


def run_pytest_suites(all_suites=False):
    """Executes pytest suite."""
    import pytest
    print(f"\n{BOLD}{CYAN}=== ETAP 2: ZESTAWY TESTÓW REGRESYJNYCH & ADWERSARYJNYCH PYTEST ==={RESET}")
    if all_suites:
        args = ["tests", "-v"]
    else:
        args = [
            "tests/test_red_team.py",
            "tests/test_dlp.py",
            "tests/test_phase2_scanner_and_deps.py",
            "tests/test_phase3_llm_zero_trust.py",
            "-v"
        ]
    print(f"Uruchamianie: pytest {' '.join(args)}\n")
    exit_code = pytest.main(args)
    return exit_code


def main():
    parser = argparse.ArgumentParser(description="AGOS 4.1 Standalone External Validation Suite")
    parser.add_argument("--probe", action="store_true", help="Run only the in-memory dynamic red-team probes")
    parser.add_argument("--all", action="store_true", help="Run all pytest test suites instead of core red-team suites")
    args = parser.parse_args()

    start_time = time.time()
    print(f"{BOLD}{YELLOW}================================================================================{RESET}")
    print(f"{BOLD}{YELLOW}          AGOS 4.1 CORE — EXTERNAL STANDALONE VALIDATION RUNNER                 {RESET}")
    print(f"{BOLD}{YELLOW}================================================================================{RESET}")
    print(f"Środowisko: Python {sys.version.split()[0]} na platformie {sys.platform}")
    print(f"Katalog roboczy: {BASE_DIR}")
    print(f"AGOS_PROVENANCE_SECRET: Ustawiony ({len(os.environ['AGOS_PROVENANCE_SECRET'])} znaków)")

    probes = run_dynamic_probes()
    probes_passed = all(p[1] for p in probes)

    pytest_passed = True
    pytest_exit = 0
    if not args.probe:
        pytest_exit = run_pytest_suites(all_suites=args.all)
        pytest_passed = (pytest_exit == 0)

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    duration = round(time.time() - start_time, 2)
    overall_ok = probes_passed and pytest_passed

    print(f"\n{BOLD}{YELLOW}================================================================================{RESET}")
    print(f"{BOLD}{YELLOW}                           PODSUMOWANIE WALIDACJI                               {RESET}")
    print(f"{BOLD}{YELLOW}================================================================================{RESET}")
    print(f"Sondy dynamiczne (14 testów) : {GREEN + '14/14 PASS' if probes_passed else RED + 'FAIL'}{RESET}")
    if not args.probe:
        print(f"Testy Pytest                 : {GREEN + 'PASS (exit code 0)' if pytest_passed else RED + f'FAIL (exit code {pytest_exit})'}{RESET}")
    print(f"Czas wykonania               : {duration}s")
    print(f"Status końcowy               : {GREEN + '[SUKCES] SYSTEM W PELNI ZWALIDOWANY (ZERO-TRUST COMPLIANT)' if overall_ok else RED + '[BLAD] WYKRYTO NARUSZENIE BEZPIECZENSTWA'}{RESET}")
    print(f"{BOLD}{YELLOW}================================================================================{RESET}\n")

    # Generate JSON summary
    summary_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "agos_version": "4.1.0",
        "platform": sys.platform,
        "python_version": sys.version,
        "overall_status": "PASS" if overall_ok else "FAIL",
        "duration_seconds": duration,
        "dynamic_probes": {k: ("PASS" if v else "FAIL") for k, v in probes},
        "pytest_exit_code": pytest_exit if not args.probe else None
    }
    with open(BASE_DIR / "EXTERNAL_VALIDATION_RESULT.json", "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)
    print(f"Zapisano raport certyfikatu do: {BASE_DIR / 'EXTERNAL_VALIDATION_RESULT.json'}")

    sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
