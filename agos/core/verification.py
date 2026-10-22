"""AGOS 3.1 Hardened Verification Gate with typed stages and Security Scanner integration."""
import ast
import re
import subprocess
import hashlib
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field
from agos.core.operation import Operation
from agos.core.state_machine import OperationState
from agos.security.sensitive_files import is_sensitive_path
from agos.security.paths import resolve_and_validate_path, SecurityPathError
from agos.core.audit import audit_trail


class StageStatus(str, Enum):
    """
    HIGH-04: Explicit verification stage statuses.
    SKIPPED != PASSED. NOT_RUN != PASSED.
    """
    NOT_RUN = "NOT_RUN"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"

    def __str__(self) -> str:
        return self.value

    @property
    def blocks_commit(self) -> bool:
        """Returns True if this status should block commit authorization."""
        return self in (StageStatus.FAILED, StageStatus.ERROR, StageStatus.NOT_RUN)


class VerificationResult(BaseModel):
    """
    HIGH-04: Typed, operation-bound verification result.
    Replaces raw dict. Bound to operation_id so stale results are detectable.
    """
    passed: bool
    operation_id: str = ""
    scope_hash: str = ""
    plan_hash: str = ""
    evidence_hash: str = ""
    diff_hash: str = ""

    # Stage-level statuses — SKIPPED != PASSED
    stage_syntax: StageStatus = StageStatus.NOT_RUN
    stage_scope: StageStatus = StageStatus.NOT_RUN
    stage_sensitive: StageStatus = StageStatus.NOT_RUN
    stage_security_scan: StageStatus = StageStatus.NOT_RUN
    stage_git_diff: StageStatus = StageStatus.NOT_RUN
    stage_plan_hash: StageStatus = StageStatus.NOT_RUN
    stage_evidence_hash: StageStatus = StageStatus.NOT_RUN
    stage_architecture: StageStatus = StageStatus.NOT_RUN
    stage_anti_amputation: StageStatus = StageStatus.NOT_RUN

    checks: Dict[str, bool] = Field(default_factory=dict)
    violations: List[str] = Field(default_factory=list)
    security_findings: List[str] = Field(default_factory=list)
    security_warnings: List[str] = Field(default_factory=list)
    architecture_findings: List[str] = Field(default_factory=list)
    diff_summary: str = ""

    def any_stage_blocks_commit(self) -> bool:
        """True if any required stage is FAILED, ERROR, or NOT_RUN."""
        required_stages = [
            self.stage_syntax,
            self.stage_scope,
            self.stage_sensitive,
            self.stage_security_scan,
            self.stage_git_diff,
            self.stage_architecture,
            self.stage_anti_amputation,
        ]
        return any(s.blocks_commit for s in required_stages)


from agos.security.dependency_guard import (
    dependency_guard,
    DependencyGuardMode,
    read_text_auto_encoding,
)
from agos.security.architecture_guard import architecture_guard

# Regex patterns for secret detection — used by security scan stage
_SECRET_PATTERNS = {
    "Hardcoded API Key": r"(?i)api[_-]?key\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]",
    "Hardcoded Password": r"(?i)password\s*=\s*['\"][^'\"]{4,}['\"]",
    "Hardcoded Secret": r"(?i)(secret|_secret|system_secret)\s*=\s*(b?['\"][^'\"]{6,}['\"])",
    "Hardcoded Token": r"(?i)token\s*=\s*['\"][a-zA-Z0-9_\-\.]{8,}['\"]",
    "Private Key Marker": r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    "HMAC/JWT Key Assignment": r"(?i)(hmac|jwt|signing)[_\s]*(key|secret)\s*=\s*b?['\"][^'\"]{6,}['\"]",
    "Connection String": r"(?i)(connection[_-]?string|database[_-]?url)\s*=\s*['\"][^'\"]{8,}['\"]",
    "AWS Access Key Pattern": r"(?i)(aws[_-]?(access[_-]?key|secret[_-]?key))\s*=\s*['\"][A-Z0-9]{16,}['\"]",
    "AWS Access Key ID Literal": r"\bAKIA[0-9A-Z]{16}\b",
    "OpenAI API Key Literal": r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{20,}\b",
    "Google Cloud/AI Key Literal": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "GitHub Token Literal": r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b",
    "Slack Token Literal": r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",
    "Hardcoded JWT Token": r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
}


def _run_security_scan_on_file(
    filepath: Path,
    ws_root: Optional[Path] = None,
) -> Tuple[StageStatus, List[str], List[str]]:
    """
    HIGH-05 + Phase 2: Runs inline security scan on a single file.
    Returns (stage_status, critical_findings, warnings).
    - Hardcoded secrets always fail the scan (INV-018).
    - AST-SAST and DependencyGuard (slopsquatting/typosquatting) are controlled by
      AGOS_SCANNER_MODE ('warn' default -> warnings; 'enforce' -> critical_findings).
    """
    from agos.tools.security import scan_python_ast_sast, run_optional_bandit

    findings: List[str] = []
    warnings: List[str] = []
    scanner_mode = DependencyGuardMode.from_env()
    try:
        content = read_text_auto_encoding(filepath)
        lines = content.splitlines()
        for i, line in enumerate(lines, start=1):
            for vuln_name, pattern in _SECRET_PATTERNS.items():
                if re.search(pattern, line):
                    findings.append(
                        f"Line {i} in '{filepath.name}': potential {vuln_name} detected."
                    )

        if scanner_mode != DependencyGuardMode.OFF:
            extra_issues: List[str] = []
            suffix = filepath.suffix.lower()
            name_lower = filepath.name.lower()

            if suffix == ".py":
                for sast_msg in scan_python_ast_sast(content):
                    extra_issues.append(f"'{filepath.name}': {sast_msg}")
                for bandit_msg in run_optional_bandit(filepath):
                    extra_issues.append(f"'{filepath.name}': {bandit_msg}")
                for dep_f in dependency_guard.scan_python_imports(content, workspace_root=ws_root):
                    extra_issues.append(f"'{filepath.name}': {dep_f.message}")
            elif name_lower.startswith("requirements") and suffix == ".txt":
                for dep_f in dependency_guard.scan_requirements_text(content):
                    extra_issues.append(f"'{filepath.name}': {dep_f.message}")

            if extra_issues:
                if scanner_mode == DependencyGuardMode.ENFORCE:
                    findings.extend(extra_issues)
                else:
                    warnings.extend(extra_issues)

        return (StageStatus.FAILED if findings else StageStatus.PASSED), findings, warnings
    except Exception as e:
        return StageStatus.ERROR, [f"Security scan error on '{filepath.name}': {e}"], []



class VerificationGate:
    """
    Mandatory Verification Gate executed before commit or stop.
    HIGH-04: Now has explicit named stages with StageStatus.
    HIGH-05: Integrates security scanner on all target files.
    SKIPPED != PASSED. NOT_RUN blocks commit.
    """

    def verify(
        self,
        operation: Operation,
        files_to_verify: Optional[List[str]] = None,
    ) -> VerificationResult:
        violations: List[str] = []
        checks: Dict[str, bool] = {}
        security_findings: List[str] = []
        security_warnings: List[str] = []
        ws_root = Path(operation.scope.workspace_root).resolve()

        result = VerificationResult(
            passed=False,
            operation_id=operation.operation_id,
            scope_hash=operation.scope_hash,
            plan_hash=operation.plan_hash,
            evidence_hash=operation.evidence_hash,
        )

        targets = files_to_verify or list(operation.scope.allowed_paths)

        # ── STAGE: scope + sensitive + syntax ───────────────────────────────
        scope_ok = True
        sensitive_ok = True
        syntax_ok = True

        for f_path in targets:
            try:
                resolved = resolve_and_validate_path(f_path, ws_root)
            except SecurityPathError as spe:
                violations.append(f"Workspace escape violation for {f_path}: {spe}")
                scope_ok = False
                continue

            # Scope containment check
            if not operation.scope.is_path_in_scope(resolved):
                violations.append(f"INV-014: Target file '{f_path}' is outside approved scope.")
                scope_ok = False

            # Sensitive file check
            if is_sensitive_path(resolved):
                violations.append(f"INV-013: Modified file is sensitive: {resolved}")
                sensitive_ok = False

            # Existence
            if not resolved.exists():
                violations.append(f"Verified target does not exist: {resolved}")
                continue

            # Syntax check for Python files
            if resolved.suffix.lower() == ".py":
                try:
                    with open(resolved, "r", encoding="utf-8-sig") as f:
                        source = f.read()
                    ast.parse(source)
                    checks[f"syntax_{resolved.name}"] = True
                except SyntaxError as se:
                    violations.append(f"Syntax error in {resolved.name} at line {se.lineno}: {se.msg}")
                    checks[f"syntax_{resolved.name}"] = False
                    syntax_ok = False
                except Exception as ex:
                    violations.append(f"Failed to read/parse {resolved.name}: {ex}")
                    checks[f"syntax_{resolved.name}"] = False
                    syntax_ok = False

        result.stage_scope = StageStatus.PASSED if scope_ok else StageStatus.FAILED
        result.stage_sensitive = StageStatus.PASSED if sensitive_ok else StageStatus.FAILED
        result.stage_syntax = StageStatus.PASSED if syntax_ok else StageStatus.FAILED

        # ── STAGE: security scan ─────────────────────────────────────────────
        # HIGH-05: Must run on every target file. NOT_RUN blocks commit.
        all_scan_passed = True
        for f_path in targets:
            try:
                resolved = resolve_and_validate_path(f_path, ws_root)
            except SecurityPathError:
                continue
            if not resolved.exists():
                continue
            stage_status, file_findings, file_warnings = _run_security_scan_on_file(resolved, ws_root)
            if file_findings:
                security_findings.extend(file_findings)
            if file_warnings:
                security_warnings.extend(file_warnings)
            if stage_status != StageStatus.PASSED:
                all_scan_passed = False

        if targets:
            result.stage_security_scan = StageStatus.PASSED if all_scan_passed else StageStatus.FAILED
            if not all_scan_passed:
                violations.append(
                    f"INV-018: Security scan found critical issues: {security_findings}"
                )
        else:
            # No targets — mark as SKIPPED (not PASSED), not blocking
            result.stage_security_scan = StageStatus.SKIPPED

        # ── STAGE: architecture hygiene (INV-042) ───────────────────────────
        all_arch_passed = True
        arch_findings: List[str] = []
        for f_path in targets:
            try:
                resolved = resolve_and_validate_path(f_path, ws_root)
            except SecurityPathError:
                continue
            if not resolved.exists():
                continue
            arch_violations = architecture_guard.check_file_hygiene(resolved)
            for v in arch_violations:
                all_arch_passed = False
                arch_findings.append(f"[{v.denial_code}] {v.message}")
                violations.append(f"{v.rule}: {v.message}")

        result.architecture_findings = arch_findings
        if targets:
            result.stage_architecture = StageStatus.PASSED if all_arch_passed else StageStatus.FAILED
        else:
            result.stage_architecture = StageStatus.SKIPPED

        # ── STAGE: anti-amputation guard (INV-041) ──────────────────────────
        all_amp_passed = True
        plan_meta = ""
        if operation.plan:
            plan_meta = str(operation.plan)
        if operation.approval and hasattr(operation.approval, "metadata") and operation.approval.metadata:
            plan_meta += " " + str(operation.approval.metadata)

        for f_path in targets:
            try:
                resolved = resolve_and_validate_path(f_path, ws_root)
            except SecurityPathError:
                continue
            if not resolved.exists():
                continue
            old_content = ""
            try:
                rel_path = resolved.relative_to(ws_root).as_posix()
                git_show = subprocess.run(
                    ["git", "show", f"HEAD:{rel_path}"],
                    cwd=str(ws_root),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if git_show.returncode == 0:
                    old_content = git_show.stdout
            except Exception:
                old_content = ""

            if old_content:
                try:
                    new_content = read_text_auto_encoding(resolved)
                    amp_violations = architecture_guard.check_anti_amputation(
                        old_content=old_content,
                        new_content=new_content,
                        filepath=resolved,
                        approval_metadata=plan_meta,
                    )
                    for av in amp_violations:
                        all_amp_passed = False
                        violations.append(f"{av.rule}: {av.message} [{av.denial_code}]")
                except Exception as amp_err:
                    # Fail-closed: an error in the anti-amputation check must never pass silently.
                    all_amp_passed = False
                    violations.append(
                        f"INV-041:CHECK_ERROR: anti-amputation check failed for '{f_path}': {amp_err} "
                        f"[ANTI_AMPUTATION_VIOLATION]"
                    )

        if targets:
            result.stage_anti_amputation = StageStatus.PASSED if all_amp_passed else StageStatus.FAILED
        else:
            result.stage_anti_amputation = StageStatus.SKIPPED

        # ── STAGE: plan hash ─────────────────────────────────────────────────
        # HIGH-02: Verify plan hasn't changed since approval
        if operation.approval and operation.approval.plan_hash and operation.plan_hash:
            current_plan_hash = operation.compute_plan_hash()
            if current_plan_hash == operation.approval.plan_hash:
                result.stage_plan_hash = StageStatus.PASSED
            else:
                result.stage_plan_hash = StageStatus.FAILED
                violations.append(
                    f"INV-015: Plan hash mismatch at verification. "
                    f"Expected '{operation.approval.plan_hash}', got '{current_plan_hash}' "
                    "[PLAN_HASH_MISMATCH]."
                )
        else:
            result.stage_plan_hash = StageStatus.SKIPPED

        # ── STAGE: evidence hash ─────────────────────────────────────────────
        # HIGH-03: Verify evidence hasn't changed since approval
        if operation.approval and operation.approval.evidence_hash and operation.evidence_hash:
            current_ev_hash = operation.compute_evidence_hash()
            if current_ev_hash == operation.approval.evidence_hash:
                result.stage_evidence_hash = StageStatus.PASSED
            else:
                result.stage_evidence_hash = StageStatus.FAILED
                violations.append(
                    f"INV-016: Evidence hash mismatch at verification. "
                    f"Expected '{operation.approval.evidence_hash}', got '{current_ev_hash}' "
                    "[EVIDENCE_HASH_MISMATCH]."
                )
        else:
            result.stage_evidence_hash = StageStatus.SKIPPED

        # ── STAGE: git diff ──────────────────────────────────────────────────
        git_diff_summary = ""
        git_ok = True
        try:
            status_res = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(ws_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if status_res.returncode == 0:
                lines = status_res.stdout.strip().split("\n")
                changed_files = []
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(maxsplit=1)
                    if len(parts) == 2:
                        raw_filename = parts[1].strip('"')
                        changed_files.append(raw_filename)

                for cf in changed_files:
                    cf_path = ws_root / cf
                    if not operation.scope.is_path_in_scope(cf_path):
                        if any(
                            line.startswith(c)
                            for c in ("M", "A", "D", "R")
                            for line in lines
                            if cf in line
                        ):
                            violations.append(
                                f"INV-014: Unexpected modified file in git working tree: {cf}"
                            )
                            git_ok = False

            diff_res = subprocess.run(
                ["git", "diff", "--stat"],
                cwd=str(ws_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if diff_res.returncode == 0:
                git_diff_summary = diff_res.stdout.strip()
                diff_bytes = git_diff_summary.encode('utf-8')
                result.diff_hash = hashlib.sha256(diff_bytes).hexdigest()

            result.stage_git_diff = StageStatus.PASSED if git_ok else StageStatus.FAILED
        except Exception as e:
            git_diff_summary = f"Git check failed: {e}"
            result.stage_git_diff = StageStatus.SKIPPED  # Git may not be present — not blocking

        # ── Final result ─────────────────────────────────────────────────────
        # passed = True ONLY if no violations AND no required stage blocks commit
        passed = (len(violations) == 0) and not result.any_stage_blocks_commit()
        result.passed = passed
        result.checks = checks
        result.violations = violations
        result.security_findings = security_findings
        result.security_warnings = security_warnings
        result.diff_summary = git_diff_summary

        audit_trail.record(
            operation_id=operation.operation_id,
            state=str(operation.state),
            action="VERIFICATION_GATE",
            target=str(targets),
            result="PASS" if passed else "FAIL",
            scope_hash=operation.scope_hash,
            reason=(
                f"Verification complete. "
                f"syntax={result.stage_syntax} scope={result.stage_scope} "
                f"sensitive={result.stage_sensitive} "
                f"security_scan={result.stage_security_scan} "
                f"arch={result.stage_architecture} "
                f"anti_amp={result.stage_anti_amputation} "
                f"git_diff={result.stage_git_diff} "
                f"Violations: {violations}"
            ),
        )

        # Store typed result on operation (as dict for backward compat)
        operation.verification = result.model_dump()
        return result


verification_gate = VerificationGate()
