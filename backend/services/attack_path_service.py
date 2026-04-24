from __future__ import annotations
from sqlalchemy.orm import Session
from models.network import NetworkDiscoveredAsset
from models.network_extensions import AttackPathFinding, ExtensionServiceJob, ExposureFinding

def _set_job(job, *, status=None, stage=None, pct=None, current_target=None, findings=None, summary=None):
    if status is not None: job.status = status
    if stage is not None: job.current_stage = stage
    if pct is not None: job.progress_percent = pct
    if current_target is not None: job.current_target = current_target
    if findings is not None: job.findings_count = findings
    if summary is not None: job.summary_json = summary

def run_attack_path_job(db: Session, *, tenant_id: str, target: str | None, requested_by: str | None, job_id: int) -> dict:
    job = db.query(ExtensionServiceJob).filter(ExtensionServiceJob.id == job_id).first()
    if not job: return {"status": "missing_job"}
    _set_job(job, status="running", stage="loading_assets", pct=10, summary={"service": "Attack Path Insight"})
    db.commit()
    assets = db.query(NetworkDiscoveredAsset).filter(NetworkDiscoveredAsset.tenant_id == tenant_id, NetworkDiscoveredAsset.is_active == True).all()
    findings = 0
    total = len(assets)
    for idx, asset in enumerate(assets, start=1):
        pct = 15 if total == 0 else min(95, 15 + int((idx / total) * 75))
        _set_job(job, stage="building_narratives", pct=pct, current_target=asset.ip_address)
        db.commit()
        raw_ports = asset.open_ports or []
        port_nums: list[int] = []
        for p in raw_ports:
            port = p.get("port") if isinstance(p, dict) else p
            if isinstance(port, int): port_nums.append(port)
        related_cves = []
        for v in (asset.vulnerabilities or []):
            if isinstance(v, dict) and v.get("cve_id"): related_cves.append(v["cve_id"])
        if 3389 in port_nums and (asset.critical_cve_count or 0) > 0:
            db.add(AttackPathFinding(tenant_id=tenant_id, job_id=job_id, asset_id=asset.id, ip_address=asset.ip_address,
                path_type="rdp_plus_critical_cves", risk_score=9.0,
                narrative=f"Host {asset.ip_address} exposes RDP and has critical CVEs. This combination increases remote access and post-compromise risk.",
                related_services_json=[str(p) for p in port_nums], related_cves_json=related_cves[:10]))
            findings += 1
        if 445 in port_nums and not asset.agent_installed:
            db.add(AttackPathFinding(tenant_id=tenant_id, job_id=job_id, asset_id=asset.id, ip_address=asset.ip_address,
                path_type="unmanaged_smb_host", risk_score=8.0,
                narrative=f"Host {asset.ip_address} is unmanaged and exposes SMB. If credentials are obtained elsewhere, this may support lateral movement.",
                related_services_json=[str(p) for p in port_nums], related_cves_json=related_cves[:10]))
            findings += 1
        if getattr(asset, 'is_internet_facing', False) and (80 in port_nums or 443 in port_nums):
            db.add(AttackPathFinding(tenant_id=tenant_id, job_id=job_id, asset_id=asset.id, ip_address=asset.ip_address,
                path_type="internet_facing_web_surface", risk_score=7.0,
                narrative=f"Host {asset.ip_address} appears internet facing and exposes web services. Validate that the exposure is intended and hardened.",
                related_services_json=[str(p) for p in port_nums], related_cves_json=related_cves[:10]))
            findings += 1
    db.commit()

    # Also generate findings from ExposureFinding table (populated by Exposure Analysis)
    exposures = db.query(ExposureFinding).filter(
        ExposureFinding.tenant_id == tenant_id,
    ).all()
    for exp in exposures:
        path_type = "internet_facing_web_surface"
        risk = 7.0
        if exp.severity in ("critical", "high"):
            path_type = "high_severity_exposure"
            risk = 9.0
        elif exp.severity == "medium":
            risk = 7.5
        # Avoid duplicates from same IP
        existing = next((f for f in db.query(AttackPathFinding).filter(
            AttackPathFinding.tenant_id == tenant_id,
            AttackPathFinding.job_id == job_id,
            AttackPathFinding.ip_address == exp.ip_address,
        ).all()), None)
        if not existing:
            db.add(AttackPathFinding(
                tenant_id=tenant_id,
                job_id=job_id,
                asset_id=exp.asset_id,
                ip_address=exp.ip_address,
                path_type=path_type,
                risk_score=risk,
                narrative=f"{exp.title} on {exp.ip_address}. {exp.description or ''} {exp.remediation or ''}".strip(),
                related_services_json=[exp.finding_type or "unknown"],
                related_cves_json=[],
            ))
            findings += 1
    db.commit()

    _set_job(job, status="completed", stage="completed", pct=100, findings=findings,
        summary={"service": "Attack Path Insight", "finding_count": findings, "asset_count": total, "progress": {"phase": "Completed", "pct": 100}})
    db.commit()
    return {"status": "completed", "finding_count": findings}
