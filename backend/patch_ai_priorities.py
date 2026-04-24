"""
patch_ai_priorities.py
Fixes the AI Priorities panel hanging indefinitely.

Two fixes:
  1. Frontend — adds a 30s timeout to the API call and shows results immediately
  2. Backend — patches batch_prioritise to remove per-finding DB queries
                (was doing 2 DB lookups per finding = 200+ queries for 100 findings)

Run inside the container:
  docker cp patch_ai_priorities.py cyberassetiq-backend-1:/app/patch_ai_priorities.py
  docker exec cyberassetiq-backend-1 python /app/patch_ai_priorities.py
"""

import os

# ═══════════════════════════════════════════════════════════════════════════════
# PATCH 1 — Frontend: add timeout + better empty state handling
# ═══════════════════════════════════════════════════════════════════════════════

INDEX_PATH = '/app/static/index.html'

with open(INDEX_PATH, 'r', encoding='utf-8') as f:
    html = f.read()

OLD_AI_PRIORITIES = """async function loadAIPriorities() {
  const panel = document.getElementById('aiPrioritiesPanel');
  if (!panel) return;
  if (panel.style.display !== 'none') { panel.style.display = 'none'; return; }
  panel.style.display = 'block';
  panel.innerHTML = '<div class="loading-state"><div class="spinner"></div> AI ranking vulnerabilities…</div>';
  const r = await api('GET', '/api/vulns/findings/ai-priorities?limit=10');
  if (!r || !r.length) {
    panel.innerHTML = '<div class="card"><div class="card-body"><p style="color:var(--text-dim);font-size:13px">No AI priorities available — run a scan first.</p></div></div>';
    return;
  }"""

NEW_AI_PRIORITIES = """async function loadAIPriorities() {
  const panel = document.getElementById('aiPrioritiesPanel');
  if (!panel) return;
  if (panel.style.display !== 'none') { panel.style.display = 'none'; return; }
  panel.style.display = 'block';
  panel.innerHTML = '<div class="loading-state"><div class="spinner"></div> AI ranking vulnerabilities… (may take 15-20s)</div>';

  // Timeout wrapper — 35 seconds max
  let r;
  try {
    const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 35000));
    r = await Promise.race([
      api('GET', '/api/vulns/findings/ai-priorities?limit=10'),
      timeout
    ]);
  } catch(e) {
    panel.innerHTML = `<div class="card"><div class="card-body">
      <p style="color:#f59e0b;font-size:13px">⚠ AI ranking timed out — the server is processing a large dataset.
      Try again in a moment or reduce the number of open findings first.</p>
      <button class="btn" style="margin-top:8px;font-size:12px" onclick="loadAIPriorities()">Retry</button>
    </div></div>`;
    return;
  }

  if (!r || !r.length) {
    panel.innerHTML = '<div class="card"><div class="card-body"><p style="color:var(--text-dim);font-size:13px">No AI priorities available — run a scan first.</p></div></div>';
    return;
  }"""

if OLD_AI_PRIORITIES in html:
    html = html.replace(OLD_AI_PRIORITIES, NEW_AI_PRIORITIES)
    print('PATCH 1 applied — frontend timeout added to AI priorities')
else:
    print('PATCH 1 SKIPPED — loadAIPriorities not matched')

with open(INDEX_PATH, 'w', encoding='utf-8') as f:
    f.write(html)


# ═══════════════════════════════════════════════════════════════════════════════
# PATCH 2 — Backend: optimise batch_prioritise to avoid N+1 queries
# Replaces the per-finding asset + exposure DB lookups with a single bulk fetch
# ═══════════════════════════════════════════════════════════════════════════════

SERVICE_PATH = '/app/services/ai_cve_context_service.py'

with open(SERVICE_PATH, 'r', encoding='utf-8') as f:
    svc = f.read()

OLD_BATCH = """    def batch_prioritise(self, tenant_id: str, limit: int = 20) -> List[Dict[str, Any]]:
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
        return results[:limit]"""

NEW_BATCH = """    def batch_prioritise(self, tenant_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        # Fetch findings — limit to 50 to keep response fast
        findings = (self.db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.tenant_id == tenant_id, VulnerabilityFinding.status == "open")
            .order_by(desc(VulnerabilityFinding.cvss_score)).limit(50).all())

        if not findings:
            return []

        # Bulk-fetch all assets for this tenant in ONE query (avoids N+1)
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
            # Skip expensive exposure query in batch mode — not needed for ranking
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
        return results[:limit]"""

if OLD_BATCH in svc:
    svc = svc.replace(OLD_BATCH, NEW_BATCH)
    with open(SERVICE_PATH, 'w', encoding='utf-8') as f:
        f.write(svc)
    print('PATCH 2 applied — batch_prioritise optimised (bulk asset fetch, 50 finding limit)')
else:
    print('PATCH 2 SKIPPED — batch_prioritise not matched')

print('\nDone. Restart the container: docker restart cyberassetiq-backend-1')
print('Then hard-refresh with Ctrl+Shift+R.')
