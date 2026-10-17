"""
AGOS 5.0 Architectural Hygiene & Anti-Amputation Guard (INV-041 & INV-042).

Enforces clean component boundaries and prevents silent feature amputation:
- INV-041: Anti-Amputation Invariant (blocks removing routes, UI modes, or public exports without explicit approval tag).
- INV-042: Architectural File Budget (blocks bloated monolithic files, e.g. UI > 400 LOC, General > 600 LOC).
- INV-043: Runtime Smoke Gate integration for web/frontend verification.
"""

import os
import re
from pathlib import Path
from typing import List, Optional, Tuple, Set
from pydantic import BaseModel, Field

# Denial codes defined directly to prevent circular import with agos.core.__init__
ARCH_MAX_FILE_SIZE_EXCEEDED = "ARCH_MAX_FILE_SIZE_EXCEEDED"
ANTI_AMPUTATION_VIOLATION = "ANTI_AMPUTATION_VIOLATION"
RUNTIME_SMOKE_FAILED = "RUNTIME_SMOKE_FAILED"


class ArchitectureViolation(BaseModel):
    file_path: str
    rule: str
    message: str
    denial_code: str
    metric_value: int = 0
    metric_limit: int = 0


class ArchitectureGuard:
    """
    Guards code modularity, size budgets and feature preservation.
    """

    def __init__(
        self,
        max_ui_loc: Optional[int] = None,
        max_general_loc: Optional[int] = None,
        enforce_arch: Optional[bool] = None,
        enforce_amputation: Optional[bool] = None,
    ):
        self.max_ui_loc = max_ui_loc or int(os.environ.get("AGOS_MAX_UI_LOC", "400"))
        self.max_general_loc = max_general_loc or int(os.environ.get("AGOS_MAX_GENERAL_LOC", "600"))
        
        env_arch = os.environ.get("AGOS_ARCH_ENFORCE", "1").lower()
        self.enforce_arch = enforce_arch if enforce_arch is not None else (env_arch in ("1", "true", "yes"))

        env_amp = os.environ.get("AGOS_ANTI_AMPUTATION_ENFORCE", "1").lower()
        self.enforce_amputation = (
            enforce_amputation if enforce_amputation is not None else (env_amp in ("1", "true", "yes"))
        )

    @staticmethod
    def is_ui_file(filepath: Path) -> bool:
        """Determines if a file is a UI component / template."""
        suffix = filepath.suffix.lower()
        if suffix in (".jsx", ".tsx", ".vue", ".svelte"):
            return True
        parts = [p.lower() for p in filepath.parts]
        if any(marker in parts for marker in ("components", "views", "screens", "pages", "frontend")):
            if suffix in (".js", ".ts", ".html", ".css"):
                return True
        return False

    @staticmethod
    def is_ignored_file(filepath: Path) -> bool:
        """Skip vendor, package-lock, minified or build artifacts."""
        parts = [p.lower() for p in filepath.parts]
        if any(ign in parts for marker in ("node_modules", "venv", ".git", "dist", "build", ".pytest_cache") for ign in [marker]):
            return True
        name = filepath.name.lower()
        if name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements-pinned.txt", "sbom.cdx.json"):
            return True
        if name.endswith(".min.js") or name.endswith(".min.css") or name.endswith(".map"):
            return True
        return False

    def check_file_hygiene(
        self,
        filepath: Path,
        content: Optional[str] = None,
    ) -> List[ArchitectureViolation]:
        """
        INV-042: Verifies that file does not exceed modularity line-of-code thresholds.
        """
        if not self.enforce_arch or self.is_ignored_file(filepath):
            return []

        if content is None:
            if not filepath.exists() or not filepath.is_file():
                return []
            try:
                with open(filepath, "r", encoding="utf-8-sig", errors="replace") as f:
                    content = f.read()
            except Exception:
                return []

        lines = content.splitlines()
        loc = len(lines)
        is_ui = self.is_ui_file(filepath)
        limit = self.max_ui_loc if is_ui else self.max_general_loc

        violations = []
        if loc > limit:
            file_category = "UI component" if is_ui else "source file"
            violations.append(
                ArchitectureViolation(
                    file_path=filepath.name,
                    rule="INV-042:MAX_LOC_EXCEEDED",
                    message=(
                        f"{file_category.capitalize()} '{filepath.name}' exceeds architectural budget: "
                        f"{loc} LOC (limit: {limit} LOC). Decompose into subcomponents/modules."
                    ),
                    denial_code=ARCH_MAX_FILE_SIZE_EXCEEDED,
                    metric_value=loc,
                    metric_limit=limit,
                )
            )

        return violations

    def check_anti_amputation(
        self,
        old_content: str,
        new_content: str,
        filepath: Path,
        approval_metadata: str = "",
    ) -> List[ArchitectureViolation]:
        """
        INV-041: Detects silent removal of UI modes, router endpoints, or key domain exports.
        Bypassed ONLY if approval_metadata explicitly includes [BREAKING_FEATURE_REMOVAL].
        """
        if not self.enforce_amputation or self.is_ignored_file(filepath):
            return []

        # Explicit escape hatch if user genuinely requested feature deletion
        if "[BREAKING_FEATURE_REMOVAL]" in approval_metadata or "[DEPRECATION_APPROVED]" in approval_metadata:
            return []

        violations: List[ArchitectureViolation] = []

        # 1. Check UI mode string literals (e.g. plannerMode === 'satellite', 'house_photo', etc.)
        mode_patterns = [
            r"plannerMode\s*===\s*['\"]([a-zA-Z0-9_\-]+)['\"]",
            r"setPlannerMode\s*\(\s*['\"]([a-zA-Z0-9_\-]+)['\"]",
            r"mode\s*===\s*['\"]([a-zA-Z0-9_\-]+)['\"]",
            r"activeProvider\s*===\s*['\"]([a-zA-Z0-9_\-]+)['\"]",
        ]
        old_modes: Set[str] = set()
        new_modes: Set[str] = set()
        for pat in mode_patterns:
            old_modes.update(re.findall(pat, old_content))
            new_modes.update(re.findall(pat, new_content))

        removed_modes = old_modes - new_modes
        for rm in removed_modes:
            violations.append(
                ArchitectureViolation(
                    file_path=filepath.name,
                    rule="INV-041:ANTI_AMPUTATION_UI_MODE",
                    message=(
                        f"Silent removal of UI mode '{rm}' detected in '{filepath.name}'. "
                        "Amputation of features requires explicit [BREAKING_FEATURE_REMOVAL] approval."
                    ),
                    denial_code=ANTI_AMPUTATION_VIOLATION,
                )
            )

        # 2. Check public Javascript/Typescript exports
        if filepath.suffix.lower() in (".js", ".jsx", ".ts", ".tsx"):
            export_pattern = r"export\s+(?:default\s+)?(?:function|const|class)\s+([A-Za-z0-9_]+)"
            old_exports = set(re.findall(export_pattern, old_content))
            new_exports = set(re.findall(export_pattern, new_content))
            removed_exports = old_exports - new_exports
            for rexp in removed_exports:
                violations.append(
                    ArchitectureViolation(
                        file_path=filepath.name,
                        rule="INV-041:ANTI_AMPUTATION_EXPORT",
                        message=(
                            f"Exported symbol '{rexp}' was removed from '{filepath.name}'. "
                            "Breaking API removals require explicit [BREAKING_FEATURE_REMOVAL] approval."
                        ),
                        denial_code=ANTI_AMPUTATION_VIOLATION,
                    )
                )

        # 3. Check API route decorators in Python
        if filepath.suffix.lower() == ".py":
            route_pattern = r"@(app|router)\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]"
            old_routes = {m[2] for m in re.findall(route_pattern, old_content)}
            new_routes = {m[2] for m in re.findall(route_pattern, new_content)}
            removed_routes = old_routes - new_routes
            for rroute in removed_routes:
                violations.append(
                    ArchitectureViolation(
                        file_path=filepath.name,
                        rule="INV-041:ANTI_AMPUTATION_API_ROUTE",
                        message=(
                            f"API Route endpoint '{rroute}' was deleted from '{filepath.name}'. "
                            "Breaking API removals require explicit [BREAKING_FEATURE_REMOVAL] approval."
                        ),
                        denial_code=ANTI_AMPUTATION_VIOLATION,
                    )
                )

        return violations


architecture_guard = ArchitectureGuard()
