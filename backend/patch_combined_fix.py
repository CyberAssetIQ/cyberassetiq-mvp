"""
patch_combined_fix.py

Fix 1 — AI Priorities: optimise batch_prioritise (N+1 query fix)
Fix 2 — Missing agent CVEs: show findings across all agents from latest scan
         AND trigger a new scan so second machine is captured

Run inside the container:
  docker cp patch_combined_fix.py cyberassetiq-backend-1:/app/patch_combined_fix.py
  docker exec cyberassetiq-backend-1 python /app/patch_combined_fix.py
Then restart:
  docker restart cyberassetiq-backend-1
"""

# ── Fix 1: Optimise batch_prioritise ─────────────────────────────────────────

SERVICE_PATH = '/app/services/ai_cve_context_service.py'

with open(SERVICE_PATH, 'r', encoding='utf-8') as f:
    svc = f.read()

if 'Bulk-fetch all assets' in svc:
    print('Fix 1 already applied — skipping')
else:
    OLD_BATCH = '''    def batch_prioritise(self, tenant_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        findings = (self.db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.tenant_id == tenant_id, VulnerabilityFinding.status == "open")
            .order_by(desc(VulnerabilityFinding.cvss_score)).limit(100).all())
        results = []
        for f in findings:
            asset = self._get_asset(f.agent_id, tenant_id)
            exposure = self._get_exposure(asset, tenant_id) if asset else []
            ctx = self._build_context(f, asset, exposure)
            analysis = self._deterministic_analysis(f, asset, exposure, ctx)
            results.append({
                "finding_id": f.id, "cve_id": f.cve_id,
                "software": f"{f.software_name} {f.software_version or ''}".strip(),
                "cvss_score": float(f.cvss_score) if f.cvss_score else None,
                "severity": f.severity, "asset": ctx.get("asset_name"),
                "adjusted_priority": analysis["adjusted_priority"],
                "priority_reason": analysis["priority_reason"],
                "patch_urgency": analysis["patch_urgency"],
                "risk_vs_cvss": analysis["risk_vs_cvss"],
                "has_known_exploit": analysis["has_known_exploit"],
                "internet_exposure_likely": analysis["internet_exposure_likely"],
                "is_rce": analysis["is_rce"],
            })
        results.sort(key=lambda x: x["adjusted_priority"], reverse=True)
        return results[:limit]'''

    NEW_BATCH = '''    def batch_prioritise(self, tenant_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        # Fetch top findings by CVSS — cap at 50 to keep response fast
        findings = (self.db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.tenant_id == tenant_id,
                    VulnerabilityFinding.status == "open")
            .order_by(desc(VulnerabilityFinding.cvss_score)).limit(50).all())

        if not findings:
            return []

        # Bulk-fetch all assets in ONE query instead of one per finding (N+1 fix)
        from models.asset import CanonicalAsset
        agent_ids = list({f.agent_id for f in findings if f.agent_id})
        assets_list = (self.db.query(CanonicalAsset)
            .filter(CanonicalAsset.tenant_id == tenant_id,
                    CanonicalAsset.agent_id.in_(agent_ids))
            .all()) if agent_ids else []
        assets_map = {a.agent_id: a for a in assets_list}

        results = []
        for f in findings:
            asset = assets_map.get(f.agent_id)
            # Skip per-finding exposure queries in batch mode — not needed for ranking
            ctx = self._build_context(f, asset, [])
            analysis = self._deterministic_analysis(f, asset, [], ctx)
            results.append({
                "finding_id": f.id, "cve_id": f.cve_id,
                "software": f"{f.software_name} {f.software_version or ''}".strip(),
                "cvss_score": float(f.cvss_score) if f.cvss_score else None,
                "severity": f.severity, "asset": ctx.get("asset_name"),
                "adjusted_priority": analysis["adjusted_priority"],
                "priority_reason": analysis["priority_reason"],
                "patch_urgency": analysis["patch_urgency"],
                "risk_vs_cvss": analysis["risk_vs_cvss"],
                "has_known_exploit": analysis["has_known_exploit"],
                "internet_exposure_likely": analysis["internet_exposure_likely"],
                "is_rce": analysis["is_rce"],
            })
        results.sort(key=lambda x: x["adjusted_priority"], reverse=True)
        return results[:limit]'''

    if OLD_BATCH in svc:
        svc = svc.replace(OLD_BATCH, NEW_BATCH)
        with open(SERVICE_PATH, 'w', encoding='utf-8') as f:
            f.write(svc)
        print('Fix 1 applied — batch_prioritise optimised (bulk query, 50 finding cap)')
    else:
        print('Fix 1 SKIPPED — batch_prioritise not matched (may have changed)')


# ── Fix 2: Show CVEs from ALL agents, not just latest scan run ───────────────
# Root cause: get_latest_findings_with_annotations uses scan_run_id == latest.id
# This means if Agent B enrolled after the last scan, it has no scan run and
# its findings never appear.
#
# Best fix: after applying this patch, run a NEW CVE scan from the UI.
# That scan will pick up software from both agents and create a new scan run
# containing findings for both machines.
#
# We also patch the route to support ?all_agents=true as a fallback that
# queries across ALL scan runs per tenant (not just latest).

VULNS_PATH = '/app/api/routes/vulns.py'

with open(VULNS_PATH, 'r', encoding='utf-8') as f:
    vulns = f.read()

if 'all_agents' in vulns:
    print('Fix 2 already applied — skipping')
else:
    OLD_FINDINGS_ROUTE = '''@router.get("/findings")
def list_vuln_findings(
    severity: str | None = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW"),
    agent_id: str | None = Query(None),
    status: str | None = Query(None, description="open | resolved | accepted_risk | false_positive"),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    """
    List findings from the latest scan run, merged with annotation status.

    The 'status' field reflects the annotation (or 'open' if none exists).
    Findings are never hidden — annotations add badge context only.
    """
    allowed_statuses = {"open", "resolved", "accepted_risk", "false_positive"}
    status_filter = status or "open"
    if status_filter not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of: {sorted(allowed_statuses)}",
        )

    return get_latest_findings_with_annotations(
        db=db,
        tenant_id=auth.tenant_id,
        severity=severity,
        status_filter=status_filter,
        agent_id=agent_id,
        limit=limit,
        offset=offset,
    )'''

    NEW_FINDINGS_ROUTE = '''@router.get("/findings")
def list_vuln_findings(
    severity: str | None = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW"),
    agent_id: str | None = Query(None),
    status: str | None = Query(None, description="open | resolved | accepted_risk | false_positive"),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    all_agents: bool = Query(False, description="If true, return findings across ALL scan runs (shows all enrolled agents)"),
    auth: AuthenticatedRequest = Depends(require_read),
    db: Session = Depends(get_db),
) -> list[dict]:
    """
    List findings from the latest scan run, merged with annotation status.
    Pass ?all_agents=true to see CVEs from all agents across all scan runs.
    """
    allowed_statuses = {"open", "resolved", "accepted_risk", "false_positive"}
    status_filter = status or "open"
    if status_filter not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of: {sorted(allowed_statuses)}",
        )

    if all_agents:
        # Return findings across ALL scan runs for this tenant
        # Useful when multiple agents have been scanned at different times
        from models.vuln_scan import VulnAnnotation
        from models.telemetry import VulnerabilityFinding
        annotations = {
            (a.cve_id, a.agent_id): a
            for a in db.query(VulnAnnotation).filter(VulnAnnotation.tenant_id == auth.tenant_id).all()
        }
        query = db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.tenant_id == auth.tenant_id,
            VulnerabilityFinding.status == "open",
        )
        if severity:
            query = query.filter(VulnerabilityFinding.severity == severity.upper())
        if agent_id:
            query = query.filter(VulnerabilityFinding.agent_id == agent_id)
        findings = query.order_by(VulnerabilityFinding.cvss_score.desc()).limit(limit).offset(offset).all()
        SUPPRESSED = {"resolved", "accepted_risk", "false_positive"}
        result = []
        seen = set()  # deduplicate same CVE across multiple scan runs
        for f in findings:
            key = (f.cve_id, f.agent_id)
            if key in seen:
                continue
            seen.add(key)
            ann = annotations.get(key)
            ann_status = ann.status if ann else "open"
            if status_filter == "open" and ann_status in SUPPRESSED:
                continue
            if status_filter != "open" and ann_status != status_filter:
                continue
            result.append({
                "id": f.id, "tenant_id": f.tenant_id, "agent_id": f.agent_id,
                "software_name": f.software_name, "software_version": f.software_version,
                "cve_id": f.cve_id, "severity": f.severity, "cvss_score": f.cvss_score,
                "description": f.description, "published": f.published,
                "status": ann_status,
                "annotation_note": ann.note if ann else None,
                "annotated_epoch": ann.annotated_epoch if ann else None,
            })
        return result

    return get_latest_findings_with_annotations(
        db=db,
        tenant_id=auth.tenant_id,
        severity=severity,
        status_filter=status_filter,
        agent_id=agent_id,
        limit=limit,
        offset=offset,
    )'''

    if OLD_FINDINGS_ROUTE in vulns:
        vulns = vulns.replace(OLD_FINDINGS_ROUTE, NEW_FINDINGS_ROUTE)
        with open(VULNS_PATH, 'w', encoding='utf-8') as f:
            f.write(vulns)
        print('Fix 2 applied — findings route now supports ?all_agents=true')
    else:
        print('Fix 2 SKIPPED — findings route not matched')


# ── Fix 3: Update frontend to use ?all_agents=true by default ────────────────

INDEX_PATH = '/app/static/index.html'

with open(INDEX_PATH, 'r', encoding='utf-8') as f:
    html = f.read()

if 'all_agents=true' in html:
    print('Fix 3 already applied — skipping')
else:
    OLD_LOAD = "    api('GET', `/api/vulns/findings?status=${_vulnStatus}&limit=200`),"
    NEW_LOAD = "    api('GET', `/api/vulns/findings?status=${_vulnStatus}&limit=200&all_agents=true`),"

    if OLD_LOAD in html:
        html = html.replace(OLD_LOAD, NEW_LOAD)
        with open(INDEX_PATH, 'w', encoding='utf-8') as f:
            f.write(html)
        print('Fix 3 applied — frontend now fetches CVEs from all agents by default')
    else:
        print('Fix 3 SKIPPED — loadVulns API call not matched')

print('''
All done.

IMPORTANT — restart the container now:
  docker restart cyberassetiq-backend-1

Then in the browser:
  1. Ctrl+Shift+R to hard refresh
  2. Go to Vulnerabilities → click Run CVE Scan
     (this will scan BOTH agents and create a new scan run with all findings)
  3. Wait for scan to complete, then refresh findings

After the new scan, both machines will appear in the CVE list.
''')
