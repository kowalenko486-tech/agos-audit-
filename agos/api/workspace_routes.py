"""Read-only workspace endpoints: file tree, file content, structured scan,
import graph, real metrics and the HTML audit report."""
import html
import time
from collections import Counter
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from agos.api.state import operations_lock, operations_store
from agos.core.approval import approval_gate
from agos.core.audit import audit_trail
from agos.core.policy import policy_engine, PolicyDecision
from agos.core.workspace_manager import workspace_manager
from agos.security.capabilities import Capability
from agos.tools import inspector
from agos.tools.inspector import InspectorError

router = APIRouter()


def _ws() -> Path:
    return Path(workspace_manager.get_current_workspace()).resolve()


def _authorize_read(cap: Capability, rel_path: str) -> None:
    """Every content read / scan goes through the central PolicyEngine (audited, fail-closed)."""
    decision = policy_engine.authorize(capability=cap, operation=None,
                                       target_path=str(_ws() / rel_path), actor="engineer_gui")
    if decision.decision != PolicyDecision.ALLOW:
        raise HTTPException(status_code=403, detail=decision.reason)


class ScanRequest(BaseModel):
    path: str = Field(..., min_length=1, max_length=1024)


@router.get("/api/files")
async def files_tree():
    return inspector.list_tree(_ws())


@router.get("/api/files/content")
async def file_content(path: str):
    try:
        inspector.resolve_readable(_ws(), path)
        _authorize_read(Capability.READ, path)
        return inspector.read_text_file(_ws(), path)
    except InspectorError as e:
        raise HTTPException(status_code=e.status, detail=str(e))


@router.post("/api/scan")
async def scan(req: ScanRequest):
    try:
        inspector.resolve_readable(_ws(), req.path)
        _authorize_read(Capability.ANALYZE, req.path)
        return inspector.scan_file(_ws(), req.path)
    except InspectorError as e:
        raise HTTPException(status_code=e.status, detail=str(e))


@router.get("/api/graph")
async def graph():
    return inspector.import_graph(_ws())


@router.get("/api/metrics")
async def metrics():
    """Counters computed from the real audit chain and live state — never hardcoded."""
    events = audit_trail.get_events()
    by_result = Counter(e.result for e in events)
    with operations_lock:
        by_state = Counter(str(op.state) for op in operations_store.values())
    approvals = Counter(str(a.status) for a in approval_gate.list_approvals())
    valid, reason = audit_trail.verify_integrity()
    return {
        "audit_events": len(events),
        "audit_valid": valid,
        "audit_reason": reason,
        "results": dict(by_result),
        "denied": by_result.get("DENY", 0),
        "operations": dict(by_state),
        "approvals": dict(approvals),
    }


_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@router.get("/api/report", response_class=HTMLResponse)
async def report():
    data = inspector.build_report(_ws())
    valid, reason = audit_trail.verify_integrity()
    e = html.escape
    rows = []
    for s in data["scanned"]:
        if not s["findings"]:
            rows.append(f"<tr><td>{e(s['path'])}</td><td>—</td><td>—</td><td class='ok'>brak znalezisk</td></tr>")
        for f in sorted(s["findings"], key=lambda f: _SEV_ORDER.index(f["severity"])):
            rows.append(
                f"<tr><td>{e(s['path'])}</td><td>{f['line']}</td>"
                f"<td class='sev-{e(f['severity'].lower())}'>{e(f['severity'])} · {e(f['rule'])}</td>"
                f"<td>{e(f['message'])}</td></tr>"
            )
    counts = " · ".join(f"{k}: {data['counts'].get(k, 0)}" for k in _SEV_ORDER)
    sensitive = "".join(f"<li>{e(p)}</li>" for p in data["sensitive_files"]) or "<li>brak</li>"
    skipped = "".join(f"<li>{e(p)}</li>" for p in data["skipped"]) or "<li>brak</li>"
    not_checked = "".join(f"<li>{e(x)}</li>" for x in data["not_checked"])
    audit_events = audit_trail.count()
    audit_state = "ZWERYFIKOWANY" if valid else "NARUSZONY"
    body = f"""<!DOCTYPE html><html lang="pl"><head><meta charset="UTF-8">
<title>Raport AGOS — {e(Path(data['workspace']).name)}</title>
<link rel="stylesheet" href="/ui/css/report.css"></head><body>
<h1>Raport bezpieczeństwa AGOS</h1>
<p class="meta">Workspace: <code>{e(data['workspace'])}</code><br>
Wygenerowano: {e(time.strftime('%Y-%m-%d %H:%M:%S'))} · Plików: {data['files_total']}
· Przeskanowanych: {len(data['scanned'])}{' · lista plików obcięta (limit)' if data['tree_truncated'] else ''}</p>
<h2>Podsumowanie</h2><p>{e(counts)}</p>
<p>Łańcuch audytu AGOS: <strong>{audit_state}</strong> ({audit_events} zdarzeń) — {e(reason)}</p>
<h2>Znaleziska</h2>
<table><thead><tr><th>Plik</th><th>Linia</th><th>Waga · reguła</th><th>Opis</th></tr></thead>
<tbody>{''.join(rows) or "<tr><td colspan='4'>Brak plików do skanowania.</td></tr>"}</tbody></table>
<h2>Pliki wrażliwe (wykryte, nieodczytywane)</h2><ul>{sensitive}</ul>
<h2>Pominięte (limit rozmiaru / binarne)</h2><ul>{skipped}</ul>
<h2>Czego ten raport NIE sprawdza</h2><ul>{not_checked}</ul>
<p class="meta">Skanery są heurystyczne (regex sekretów, AST-SAST, dependency guard, budżet LOC).
Brak znalezisk nie oznacza braku podatności.</p>
</body></html>"""
    audit_trail.record(operation_id="NO-OP", state="READ_ONLY", action="GENERATE_REPORT",
                       target=data["workspace"], result="SUCCESS", actor="engineer_gui")
    return HTMLResponse(body)
