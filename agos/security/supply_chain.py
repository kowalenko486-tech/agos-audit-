"""
AGOS 3.1/3.2 — Supply Chain Security & CycloneDX SBOM Generator (Phase 5).

Zero-dependency module providing:
  1. Strict lockfile verification (`verify_pinned_requirements`):
     - Ensures every dependency in `requirements-pinned.txt` uses exact `==` pinning.
     - Optional `--hash=sha256:<64-hex>` enforcement for `--require-hashes` workflows.
     - Validates all entries against `DependencyGuard` (slopsquatting/typosquatting check).
  2. CycloneDX 1.5 JSON SBOM generation (`generate_cyclonedx_sbom`):
     - Produces standards-compliant Software Bill of Materials (`bomFormat: "CycloneDX"`, `specVersion: "1.5"`).
     - Generates Package URLs (`purl: pkg:pypi/<name>@<version>`) and SHA-256 component hashes
       from installed distribution metadata (`importlib.metadata`) or lockfile hashes.
  3. CLI entrypoint (`python -m agos.security.supply_chain --output sbom.cdx.json`).
"""
import argparse
import hashlib
import importlib.metadata
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from agos.security.dependency_guard import (
    _normalize_pkg,
    dependency_guard,
    read_text_auto_encoding,
)

_PINNED_LINE_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._\-]*)==([A-Za-z0-9._+\-]+)(?:\s+--hash=sha256:([0-9a-fA-F]{64}))?$"
)
_SHA256_HASH_RE = re.compile(r"--hash=sha256:([0-9a-fA-F]{64})")


def verify_pinned_requirements(
    content: str,
    require_hashes: bool = False,
) -> Tuple[bool, List[str]]:
    """
    Verifies that a lockfile contains only strictly pinned (`pkg==version`) dependencies,
    passes `DependencyGuard`, and optionally includes `--hash=sha256:<64-hex>` digests.
    Returns `(passed, violations)`.
    """
    violations: List[str] = []
    parsed_count = 0

    for idx, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        # Handle line continuations backslashes
        line = line.rstrip("\\").strip()
        if not line or line.startswith("--"):
            continue

        if "==" not in line:
            violations.append(
                f"Line {idx}: Dependency '{line}' is not strictly pinned with '=='."
            )
            continue

        head_part = line.split()[0]
        parts = head_part.split("==", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            violations.append(f"Line {idx}: Invalid pin syntax '{line}'.")
            continue

        pkg_name, version = parts[0], parts[1]
        parsed_count += 1

        # Check DependencyGuard allowlist & typosquatting
        dep_finding = dependency_guard.check_package(pkg_name, line=idx)
        if dep_finding is not None:
            violations.append(dep_finding.message)

        if require_hashes:
            if not _SHA256_HASH_RE.search(line):
                violations.append(
                    f"Line {idx}: Package '{pkg_name}=={version}' is missing '--hash=sha256:<64-hex>'."
                )

    if parsed_count == 0:
        violations.append("Lockfile contains no pinned dependency entries.")

    return (len(violations) == 0), violations


def _compute_installed_dist_sha256(pkg_name: str, version: str) -> str:
    """
    Computes a deterministic SHA-256 hash from the installed package's RECORD/METADATA
    via `importlib.metadata` (or falls back to canonical purl digest if not installed locally).
    """
    candidates = [pkg_name, _normalize_pkg(pkg_name), pkg_name.replace("-", "_")]
    for cand in candidates:
        try:
            dist = importlib.metadata.distribution(cand)
            rec = dist.read_text("RECORD") or dist.read_text("METADATA") or ""
            if rec:
                return hashlib.sha256(rec.encode("utf-8")).hexdigest()
        except Exception:
            continue
    canonical_id = f"pkg:pypi/{_normalize_pkg(pkg_name)}@{version}"
    return hashlib.sha256(canonical_id.encode("utf-8")).hexdigest()


def generate_cyclonedx_sbom(
    requirements_lock_path: Path,
    project_name: str = "agos-core",
    project_version: str = "4.1.0",
) -> Dict[str, Any]:
    """
    Generates a CycloneDX 1.5 JSON SBOM from a pinned requirements file.
    """
    content = read_text_auto_encoding(requirements_lock_path)
    components: List[Dict[str, Any]] = []

    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip().rstrip("\\").strip()
        if not line or line.startswith("--") or "==" not in line:
            continue
        head_part = line.split()[0]
        pkg_name, version = head_part.split("==", 1)
        norm_name = _normalize_pkg(pkg_name)
        purl = f"pkg:pypi/{norm_name}@{version}"

        hash_match = _SHA256_HASH_RE.search(line)
        sha256_hex = (
            hash_match.group(1).lower()
            if hash_match
            else _compute_installed_dist_sha256(pkg_name, version)
        )

        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": norm_name,
                "version": version,
                "purl": purl,
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": sha256_hex,
                    }
                ],
            }
        )

    sbom: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "application",
                "bom-ref": f"pkg:generic/{project_name}@{project_version}",
                "name": project_name,
                "version": project_version,
            },
        },
        "components": components,
    }
    return sbom


def write_cyclonedx_sbom(
    requirements_lock_path: Path,
    output_path: Path,
    project_name: str = "agos-core",
    project_version: str = "4.1.0",
) -> Dict[str, Any]:
    """Generates and writes a CycloneDX 1.5 JSON SBOM to `output_path`."""
    sbom = generate_cyclonedx_sbom(
        requirements_lock_path=requirements_lock_path,
        project_name=project_name,
        project_version=project_version,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sbom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return sbom


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="AGOS Supply Chain Verifier & CycloneDX SBOM Generator")
    parser.add_argument(
        "--lockfile",
        default="requirements-pinned.txt",
        help="Path to pinned requirements lockfile (default: requirements-pinned.txt)",
    )
    parser.add_argument(
        "--output",
        default="sbom.cdx.json",
        help="Output path for CycloneDX 1.5 JSON SBOM",
    )
    parser.add_argument(
        "--require-hashes",
        action="store_true",
        help="Require --hash=sha256:... on every pinned line",
    )
    args = parser.parse_args(argv)

    lock_path = Path(args.lockfile).resolve()
    if not lock_path.exists():
        print(f"[SUPPLY_CHAIN ERROR] Lockfile not found: {lock_path}")
        return 1

    content = read_text_auto_encoding(lock_path)
    passed, violations = verify_pinned_requirements(content, require_hashes=args.require_hashes)
    if not passed:
        print("[SUPPLY_CHAIN FAILED] Lockfile verification failed:")
        for v in violations:
            print(f"  - {v}")
        return 1

    out_path = Path(args.output).resolve()
    sbom = write_cyclonedx_sbom(lock_path, out_path)
    print(
        f"[SUPPLY_CHAIN OK] Verified {len(sbom['components'])} pinned packages and generated SBOM: {out_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
