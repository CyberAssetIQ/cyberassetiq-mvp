from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
if (ROOT / 'backend').exists():
    project_root = ROOT
elif (ROOT / 'cyberassetiq' / 'backend').exists():
    project_root = ROOT / 'cyberassetiq'
else:
    raise SystemExit('Could not find project root containing backend/')

# 1) Patch nvd_service.py
nvd_path = project_root / 'backend' / 'services' / 'nvd_service.py'
text = nvd_path.read_text(encoding='utf-8')

if 'def get_effective_findings_across_history(' not in text:
    helper = '''

def get_effective_findings_across_history(
    db: Session, tenant_id: str,
    severity: str | None = None, status_filter: str = "open",
    agent_id: str | None = None, source: str | None = None,
    limit: int = 200, offset: int = 0,
) -> list[dict[str, Any]]:
    """Return one effective finding per (agent_id, cve_id) across history.

    Newest row wins. If the newest row is not from the latest completed scan,
    it is surfaced as archived so old immutable findings do not remain open.
    """
    latest = get_latest_scan_run(db, tenant_id)
    if not latest:
        return []

    annotations: dict[tuple[str, str], VulnAnnotation] = {
        (a.cve_id, a.agent_id): a
        for a in db.query(VulnAnnotation).filter(VulnAnnotation.tenant_id == tenant_id).all()
    }

    query = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.tenant_id == tenant_id)
    if severity:
        query = query.filter(VulnerabilityFinding.severity == severity.upper())
    if agent_id:
        query = query.filter(VulnerabilityFinding.agent_id == agent_id)
    if source:
        query = query.filter(VulnerabilityFinding.source == source)

    findings = query.order_by(
        VulnerabilityFinding.scan_run_id.desc().nullslast(),
        VulnerabilityFinding.scan_epoch.desc().nullslast(),
        VulnerabilityFinding.cvss_score.desc().nullslast(),
        VulnerabilityFinding.id.desc(),
    ).all()

    SUPPRESSED = {"resolved", "accepted_risk", "false_positive"}
    effective: dict[tuple[str, str], dict[str, Any]] = {}

    for f in findings:
        key = (f.agent_id, f.cve_id)
        if key in effective:
            continue

        ann = annotations.get((f.cve_id, f.agent_id))
        ann_status = ann.status if ann else "open"
        effective_status = ann_status
        if ann_status == "open" and f.scan_run_id != latest.id:
            effective_status = "archived"

        if status_filter == "open" and effective_status in SUPPRESSED.union({"archived"}):
            continue
        if status_filter != "open" and effective_status != status_filter:
            continue

        effective[key] = {
            "id": f.id, "scan_run_id": f.scan_run_id,
            "tenant_id": f.tenant_id, "agent_id": f.agent_id,
            "source": getattr(f, "source", "agent"),
            "software_name": f.software_name, "software_version": f.software_version,
            "cve_id": f.cve_id, "severity": f.severity, "cvss_score": f.cvss_score,
            "description": f.description, "published": f.published,
            "status": effective_status,
            "annotation_id": ann.id if ann else None,
            "annotation_note": ann.note if ann else None,
            "annotated_by": ann.annotated_by if ann else None,
            "annotated_epoch": ann.annotated_epoch if ann else None,
            "is_archived": effective_status == "archived",
            "latest_scan_run_id": latest.id,
        }

    rows = list(effective.values())
    rows.sort(key=lambda x: ((x.get("cvss_score") or 0), x.get("published") or ""), reverse=True)
    return rows[offset: offset + limit]
'''
    marker = 'def get_latest_findings_with_annotations(\n'
    idx = text.find(marker)
    if idx == -1:
        raise SystemExit('Could not find insertion point in nvd_service.py')
    text = text[:idx] + helper + text[idx:]

pattern = re.compile(r"def get_latest_findings_with_annotations\([\s\S]*?return result\[offset: offset \+ limit\]\n", re.M)
replacement = '''def get_latest_findings_with_annotations(
    db: Session, tenant_id: str,
    severity: str | None = None, status_filter: str = "open",
    agent_id: str | None = None, source: str | None = None,
    limit: int = 200, offset: int = 0,
) -> list[dict[str, Any]]:
    latest = get_latest_scan_run(db, tenant_id)
    if not latest:
        return []
    annotations: dict[tuple[str, str], VulnAnnotation] = {
        (a.cve_id, a.agent_id): a
        for a in db.query(VulnAnnotation).filter(VulnAnnotation.tenant_id == tenant_id).all()
    }
    query = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.scan_run_id == latest.id)
    if severity:
        query = query.filter(VulnerabilityFinding.severity == severity.upper())
    if agent_id:
        query = query.filter(VulnerabilityFinding.agent_id == agent_id)
    if source:
        query = query.filter(VulnerabilityFinding.source == source)
    findings = query.order_by(
        VulnerabilityFinding.cvss_score.desc().nullslast(),
        VulnerabilityFinding.id.desc(),
    ).all()

    SUPPRESSED = {"resolved", "accepted_risk", "false_positive"}
    result = []
    seen: set[tuple[str, str]] = set()
    for f in findings:
        dedupe_key = (f.agent_id, f.cve_id)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        ann = annotations.get((f.cve_id, f.agent_id))
        ann_status = ann.status if ann else "open"
        if status_filter == "open" and ann_status in SUPPRESSED:
            continue
        if status_filter != "open" and ann_status != status_filter:
            continue
        result.append({
            "id": f.id, "scan_run_id": f.scan_run_id,
            "tenant_id": f.tenant_id, "agent_id": f.agent_id,
            "source": getattr(f, "source", "agent"),
            "software_name": f.software_name, "software_version": f.software_version,
            "cve_id": f.cve_id, "severity": f.severity, "cvss_score": f.cvss_score,
            "description": f.description, "published": f.published,
            "status": ann_status,
            "annotation_id": ann.id if ann else None,
            "annotation_note": ann.note if ann else None,
            "annotated_by": ann.annotated_by if ann else None,
            "annotated_epoch": ann.annotated_epoch if ann else None,
        })
    return result[offset: offset + limit]
'''
text, count = pattern.subn(replacement, text, count=1)
if count != 1:
    raise SystemExit('Could not replace get_latest_findings_with_annotations in nvd_service.py')

nvd_path.write_text(text, encoding='utf-8')
print('Patched', nvd_path)

# 2) Patch vulns.py
vulns_path = project_root / 'backend' / 'api' / 'routes' / 'vulns.py'
text = vulns_path.read_text(encoding='utf-8')
if 'get_effective_findings_across_history' not in text:
    text = text.replace(
        '    get_all_annotations,\n    get_latest_findings_with_annotations,\n',
        '    get_all_annotations,\n    get_effective_findings_across_history,\n    get_latest_findings_with_annotations,\n'
    )
text = text.replace(
    '{"open", "resolved", "accepted_risk", "false_positive"}',
    '{"open", "resolved", "accepted_risk", "false_positive", "archived"}'
)
pattern = re.compile(r"\n    if all_agents:\n(?:[\s\S]*?)\n    return get_latest_findings_with_annotations\(", re.M)
replacement = '''
    if all_agents:
        return get_effective_findings_across_history(
            db=db,
            tenant_id=auth.tenant_id,
            severity=severity,
            status_filter=status_filter,
            agent_id=agent_id,
            limit=limit,
            offset=offset,
        )

    return get_latest_findings_with_annotations('''
text, count = pattern.subn(replacement, text, count=1)
if count != 1:
    raise SystemExit('Could not replace all_agents block in vulns.py')

vulns_path.write_text(text, encoding='utf-8')
print('Patched', vulns_path)

# 3) Patch index.html
html_path = project_root / 'backend' / 'static' / 'index.html'
html = html_path.read_text(encoding='utf-8')
if '>Archived<' not in html:
    html = html.replace(
        "            <button class=\"vuln-status-tab\" data-status=\"resolved\" onclick=\"setVulnStatus('resolved')\">Resolved</button>",
        "            <button class=\"vuln-status-tab\" data-status=\"resolved\" onclick=\"setVulnStatus('resolved')\">Resolved</button>\n            <button class=\"vuln-status-tab\" data-status=\"archived\" onclick=\"setVulnStatus('archived')\">Archived</button>"
    )
html = html.replace(
    "    api('GET', `/api/vulns/findings?status=${_vulnStatus}&limit=500`),",
    "    api('GET', `/api/vulns/findings?status=${_vulnStatus}&limit=500&all_agents=true`),"
)
html_path.write_text(html, encoding='utf-8')
print('Patched', html_path)

print('Done. Restart the backend/app after applying this patch.')
