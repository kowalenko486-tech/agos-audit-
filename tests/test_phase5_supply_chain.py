"""Tests for Phase 5: Supply Chain Security, Lockfile Verification & CycloneDX 1.5 SBOM Generation."""
import json
from pathlib import Path
import pytest

from agos.security.dependency_guard import read_text_auto_encoding
from agos.security.supply_chain import (
    generate_cyclonedx_sbom,
    main as supply_chain_cli,
    verify_pinned_requirements,
    write_cyclonedx_sbom,
)


def test_verify_pinned_requirements_passes_actual_repo_lockfile():
    repo_root = Path(__file__).resolve().parent.parent
    lock_path = repo_root / "requirements-pinned.txt"
    content = read_text_auto_encoding(lock_path)

    passed, violations = verify_pinned_requirements(content, require_hashes=False)
    assert passed is True, f"Lockfile verification failed: {violations}"
    assert violations == []


def test_verify_pinned_requirements_rejects_unpinned_or_typosquatted_entries():
    bad_lock = (
        "pydantic>=2.0.0\n"
        "reqeusts==2.31.0\n"
        "chatgpt-helper==1.0.0\n"
    )
    passed, violations = verify_pinned_requirements(bad_lock, require_hashes=False)
    assert passed is False
    assert len(violations) == 3
    assert "not strictly pinned with '=='" in violations[0]
    assert "requests" in violations[1]
    assert "slopsquatting" in violations[2]


def test_verify_pinned_requirements_enforces_sha256_hashes_when_requested():
    valid_hash = "a" * 64
    lock_with_hashes = f"pydantic==2.13.5 --hash=sha256:{valid_hash}\n"
    passed_ok, violations_ok = verify_pinned_requirements(lock_with_hashes, require_hashes=True)
    assert passed_ok is True
    assert violations_ok == []

    lock_missing_hash = "pydantic==2.13.5\n"
    passed_fail, violations_fail = verify_pinned_requirements(lock_missing_hash, require_hashes=True)
    assert passed_fail is False
    assert any("missing '--hash=sha256:" in v for v in violations_fail)


def test_generate_cyclonedx_sbom_structure_and_hashes():
    repo_root = Path(__file__).resolve().parent.parent
    lock_path = repo_root / "requirements-pinned.txt"

    sbom = generate_cyclonedx_sbom(lock_path, project_name="agos-core", project_version="3.2.0")
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["serialNumber"].startswith("urn:uuid:")
    assert sbom["metadata"]["component"]["name"] == "agos-core"
    assert len(sbom["components"]) >= 40

    first_comp = sbom["components"][0]
    assert first_comp["type"] == "library"
    assert first_comp["purl"].startswith("pkg:pypi/")
    assert len(first_comp["hashes"]) == 1
    assert first_comp["hashes"][0]["alg"] == "SHA-256"
    assert len(first_comp["hashes"][0]["content"]) == 64


def test_supply_chain_cli_writes_valid_sbom_file(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent
    lock_path = repo_root / "requirements-pinned.txt"
    out_sbom = tmp_path / "sbom.cdx.json"

    exit_code = supply_chain_cli(["--lockfile", str(lock_path), "--output", str(out_sbom)])
    assert exit_code == 0
    assert out_sbom.exists()

    loaded = json.loads(out_sbom.read_text(encoding="utf-8"))
    assert loaded["bomFormat"] == "CycloneDX"
    assert loaded["specVersion"] == "1.5"
