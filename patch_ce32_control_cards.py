from pathlib import Path
from datetime import datetime

path = Path("backend/static/index.html")
text = path.read_text(encoding="utf-8")
backup = path.with_suffix(f".html.bak_ce32_cards_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
backup.write_text(text, encoding="utf-8")

old = """async function renderCE32Page(data, el) {
  const controlSummary = data.control_summary || {};
  const runs = await loadCE32Runs().catch(() => []);
  const controlNames = ceControlNameMap();
  const controls = ['A1','A2','A3','A4','A5','A6','A7','A8'].map(id => {
    const c = controlSummary[id] || {};
    return {
      control_id: id,
      name: c.name || controlNames[id] || id,
      status: c.status || 'NOT_ASSESSED',
      average_score: c.average_score ?? 0,
      pass_count: c.pass_count ?? 0,
      partial_count: c.partial_count ?? 0,
      fail_count: c.fail_count ?? 0,
      not_assessed_count: c.not_assessed_count ?? 0,
      affected_assets: c.affected_assets || [],
      top_findings: c.top_findings || [],
    };
  });"""

new = """async function renderCE32Page(data, el) {
  const runs = await loadCE32Runs().catch(() => []);
  const controlNames = ceControlNameMap();

  // Build control summary from real backend shape:
  // /api/compliance/tenant returns data.assets[].controls, not data.control_summary.
  const assets = Array.isArray(data.assets) ? data.assets : [];
  const controlSummary = data.control_summary || {};

  for (const asset of assets) {
    const assetControls = asset.controls || {};
    for (const id of ['A1','A2','A3','A4','A5','A6','A7','A8']) {
      const c = assetControls[id];
      if (!c) continue;

      if (!controlSummary[id]) {
        controlSummary[id] = {
          name: c.name || controlNames[id] || id,
          scores: [],
          pass_count: 0,
          partial_count: 0,
          fail_count: 0,
          not_assessed_count: 0,
          affected_assets: [],
          top_findings: []
        };
      }

      const s = String(c.status || 'NOT_ASSESSED').toUpperCase();
      controlSummary[id].scores.push(Number(c.score || 0));

      if (s === 'PASS') controlSummary[id].pass_count += 1;
      else if (s === 'PARTIAL') controlSummary[id].partial_count += 1;
      else if (s === 'FAIL') controlSummary[id].fail_count += 1;
      else controlSummary[id].not_assessed_count += 1;

      if (s !== 'PASS') {
        controlSummary[id].affected_assets.push({
          agent_id: asset.agent_id,
          hostname: asset.hostname,
          asset_source: asset.asset_source,
          status: s,
          score: c.score,
          findings: c.findings || []
        });
      }

      (c.findings || []).forEach(f => {
        if (controlSummary[id].top_findings.length < 3) controlSummary[id].top_findings.push(f);
      });
    }
  }

  const controls = ['A1','A2','A3','A4','A5','A6','A7','A8'].map(id => {
    const c = controlSummary[id] || {};
    const total = (c.pass_count || 0) + (c.partial_count || 0) + (c.fail_count || 0) + (c.not_assessed_count || 0);
    let status = 'NOT_ASSESSED';
    if ((c.fail_count || 0) > 0) status = 'FAIL';
    else if ((c.partial_count || 0) > 0) status = 'PARTIAL';
    else if ((c.pass_count || 0) > 0 && total > 0) status = 'PASS';

    const avg = Array.isArray(c.scores) && c.scores.length
      ? (c.scores.reduce((a,b) => a + b, 0) / c.scores.length).toFixed(2)
      : (c.average_score ?? 0);

    return {
      control_id: id,
      name: c.name || controlNames[id] || id,
      status,
      average_score: avg,
      pass_count: c.pass_count ?? 0,
      partial_count: c.partial_count ?? 0,
      fail_count: c.fail_count ?? 0,
      not_assessed_count: c.not_assessed_count ?? 0,
      affected_assets: c.affected_assets || [],
      top_findings: c.top_findings || [],
    };
  });"""

if old not in text:
    raise SystemExit("Target block not found. No changes made.")

path.write_text(text.replace(old, new), encoding="utf-8")
print(f"Patched CE v3.2 control cards. Backup: {backup}")