"""
Tests for AGOS 5.0 Architectural Hygiene & Anti-Amputation Guard (INV-041 & INV-042).
"""

import pytest
from pathlib import Path
from agos.security.architecture_guard import ArchitectureGuard, architecture_guard
from agos.core.denial_codes import ARCH_MAX_FILE_SIZE_EXCEEDED, ANTI_AMPUTATION_VIOLATION
from agos.core.verification import VerificationGate, StageStatus
from agos.core.operation import Operation
from agos.core.scope import ExecutionScope


def test_architecture_guard_loc_limit_passed(tmp_path):
    guard = ArchitectureGuard(max_ui_loc=400, max_general_loc=600)
    small_ui = tmp_path / "Button.jsx"
    small_ui.write_text("export default function Button() { return <button>OK</button>; }\n", encoding="utf-8")

    violations = guard.check_file_hygiene(small_ui)
    assert len(violations) == 0


def test_architecture_guard_ui_loc_limit_failed(tmp_path):
    guard = ArchitectureGuard(max_ui_loc=400, max_general_loc=600)
    bloated_ui = tmp_path / "RoofPlannerView.jsx"
    # Create 450 lines of code (exceeding 400 LOC limit)
    bloated_ui.write_text("\n".join([f"// line {i}" for i in range(450)]), encoding="utf-8")

    violations = guard.check_file_hygiene(bloated_ui)
    assert len(violations) == 1
    assert violations[0].denial_code == ARCH_MAX_FILE_SIZE_EXCEEDED
    assert violations[0].metric_value == 450
    assert violations[0].metric_limit == 400
    assert "exceeds architectural budget" in violations[0].message


def test_architecture_guard_general_loc_limit_failed(tmp_path):
    guard = ArchitectureGuard(max_ui_loc=400, max_general_loc=600)
    bloated_py = tmp_path / "big_service.py"
    bloated_py.write_text("\n".join([f"x_{i} = {i}" for i in range(650)]), encoding="utf-8")

    violations = guard.check_file_hygiene(bloated_py)
    assert len(violations) == 1
    assert violations[0].denial_code == ARCH_MAX_FILE_SIZE_EXCEEDED
    assert violations[0].metric_value == 650
    assert violations[0].metric_limit == 600


def test_architecture_guard_ignores_vendor(tmp_path):
    guard = ArchitectureGuard(max_ui_loc=400, max_general_loc=600)
    vendor_dir = tmp_path / "node_modules" / "some-lib"
    vendor_dir.mkdir(parents=True)
    vendor_file = vendor_dir / "bundle.js"
    vendor_file.write_text("\n".join([f"// vendor line {i}" for i in range(1000)]), encoding="utf-8")

    violations = guard.check_file_hygiene(vendor_file)
    assert len(violations) == 0


def test_anti_amputation_ui_mode_removal_failed(tmp_path):
    guard = ArchitectureGuard()
    fpath = tmp_path / "RoofPlannerView.jsx"
    old_content = """
    function RoofPlannerView() {
        const [plannerMode, setPlannerMode] = useState('house_photo');
        return (
            <div>
                {plannerMode === 'satellite' && <SatelliteView />}
                {plannerMode === 'house_photo' && <PhotoView />}
                <button onClick={() => setPlannerMode('satellite')}>Satelita</button>
            </div>
        );
    }
    """
    # New content amputates 'satellite' mode
    new_content = """
    function RoofPlannerView() {
        const [plannerMode, setPlannerMode] = useState('house_photo');
        return (
            <div>
                {plannerMode === 'house_photo' && <PhotoView />}
            </div>
        );
    }
    """
    violations = guard.check_anti_amputation(
        old_content=old_content,
        new_content=new_content,
        filepath=fpath,
        approval_metadata="",
    )
    assert len(violations) == 1
    assert violations[0].denial_code == ANTI_AMPUTATION_VIOLATION
    assert "satellite" in violations[0].message


def test_anti_amputation_allowed_with_explicit_approval_flag(tmp_path):
    guard = ArchitectureGuard()
    fpath = tmp_path / "RoofPlannerView.jsx"
    old_content = "if (plannerMode === 'satellite') { render(); }"
    new_content = "if (plannerMode === 'house_photo') { render(); }"

    # Approval metadata contains the designated escape flag
    violations = guard.check_anti_amputation(
        old_content=old_content,
        new_content=new_content,
        filepath=fpath,
        approval_metadata="[BREAKING_FEATURE_REMOVAL] User approved removing legacy mode",
    )
    assert len(violations) == 0


def test_anti_amputation_export_removal(tmp_path):
    guard = ArchitectureGuard()
    fpath = tmp_path / "geometry.js"
    old_content = """
    export function calculateRoofSlope() { return 35; }
    export function computeModuleCorners() { return []; }
    """
    new_content = """
    export function calculateRoofSlope() { return 35; }
    """
    violations = guard.check_anti_amputation(
        old_content=old_content,
        new_content=new_content,
        filepath=fpath,
    )
    assert len(violations) == 1
    assert violations[0].denial_code == ANTI_AMPUTATION_VIOLATION
    assert "computeModuleCorners" in violations[0].message


def test_anti_amputation_api_route_removal(tmp_path):
    guard = ArchitectureGuard()
    fpath = tmp_path / "router.py"
    old_content = """
    @router.get("/api/v1/satellite-tiles")
    def get_tiles(): pass

    @router.post("/api/v1/calculate-layout")
    def calc(): pass
    """
    new_content = """
    @router.post("/api/v1/calculate-layout")
    def calc(): pass
    """
    violations = guard.check_anti_amputation(
        old_content=old_content,
        new_content=new_content,
        filepath=fpath,
    )
    assert len(violations) == 1
    assert violations[0].denial_code == ANTI_AMPUTATION_VIOLATION
    assert "/api/v1/satellite-tiles" in violations[0].message


def test_verification_gate_integration_with_architecture_violation(tmp_path):
    ws = tmp_path
    bloated = ws / "RoofPlannerView.jsx"
    bloated.write_text("\n".join([f"// line {i}" for i in range(500)]), encoding="utf-8")

    scope = ExecutionScope(workspace_root=str(ws), allowed_paths=["RoofPlannerView.jsx"])
    op = Operation(scope=scope)

    gate = VerificationGate()
    result = gate.verify(op, files_to_verify=["RoofPlannerView.jsx"])

    assert result.passed is False
    assert result.stage_architecture == StageStatus.FAILED
    assert any("INV-042:MAX_LOC_EXCEEDED" in v for v in result.violations)
    assert any(ARCH_MAX_FILE_SIZE_EXCEEDED in v for v in result.architecture_findings)
