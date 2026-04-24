from pathlib import Path
from datetime import datetime
import re

path = Path("backend/static/index.html")
text = path.read_text(encoding="utf-8")

backup = path.with_suffix(f".html.bak_ce32_drilldown_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
backup.write_text(text, encoding="utf-8")

# 1. Store CE32 computed data globally for drilldown popup
start = text.index("async function renderCE32Page(data, el)")
insert_at = text.index("  el.innerHTML = `", start)

marker = "window.__ce32ControlSummary"
if marker not in text[start:insert_at]:
    inject = """
  // Store computed CE v3.2 estate view for drilldown modals.
  window.__ce32TenantData = data;
  window.__ce32ControlSummary = controlSummary;
  window.__ce32Assets = assets;
  window.__ce32Controls = controls;

"""
    text = text[:insert_at] + inject + text[insert_at:]

# 2. Replace showCE32Control with estate-wide drilldown modal
pattern = r"async function showCE32Control\(controlId\)\s*\{.*?\n\}\s*\nasync function renderCE32Page"

replacement = r"""function showCE32Control(controlId) {
  const id = String(controlId || '').toUpperCase();
  const summary = (window.__ce32ControlSummary || {})[id] || {};
  const assets = Array.isArray(window.__ce32Assets) ? window.__ce32Assets : [];
  const controlNames = ceControlNameMap();
  const name = summary.name || controlNames[id] || id;

  const pass = summary.pass_count || 0;
  const partial = summary.partial_count || 0;
  const fail = summary.fail_count || 0;
  const notAssessed = summary.not_assessed_count || 0;

  let status = 'NOT_ASSESSED';
  if (fail > 0) status = 'FAIL';
  else if (partial > 0) status = 'PARTIAL';
  else if (pass > 0) status = 'PASS';

  const scores = Array.isArray(summary.scores) ? summary.scores : [];
  const averageScore = scores.length
    ? (scores.reduce((a, b) => a + Number(b || 0), 0) / scores.length).toFixed(2)
    : (summary.average_score ?? 0);

  let affected = Array.isArray(summary.affected_assets) ? summary.affected_assets : [];

  if (!affected.length) {
    affected = assets
      .map(asset => {
        const c = asset.controls && asset.controls[id];
        if (!c) return null;
        const s = String(c.status || 'NOT_ASSESSED').toUpperCase();
        if (s === 'PASS') return null;
        return {
          agent_id: asset.agent_id,
          hostname: asset.hostname,
          asset_source: asset.asset_source,
          overall: asset.overall_status,
          status: s,
          score: c.score,
          findings: c.findings || [],
          remediation: c.remediation || []
        };
      })
      .filter(Boolean);
  }

  const allFindings = [];
  const allRemediation = [];

  assets.forEach(asset => {
    const c = asset.controls && asset.controls[id];
    if (!c) return;
    (c.findings || []).forEach(f => {
      if (f && !allFindings.includes(f)) allFindings.push(f);
    });
    (c.remediation || []).forEach(r => {
      if (r && !allRemediation.includes(r)) allRemediation.push(r);
    });
  });

  const existing = document.getElementById('ce32-control-modal');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'ce32-control-modal';
  overlay.style.cssText = `
    position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:9999;
    display:flex;align-items:center;justify-content:center;padding:24px;
  `;

  overlay.innerHTML = `
    <div style="width:min(1380px,96vw);max-height:92vh;overflow:auto;background:var(--navy2);border:1px solid var(--border);border-radius:14px;box-shadow:0 20px 80px rgba(0,0,0,.55)">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;padding:26px 30px 10px">
        <div>
          <h2 style="margin:0 0 12px;font-size:22px;color:var(--white)">${escapeHtml(id)} · ${escapeHtml(name)}</h2>
          <div>${ceStatusChip(status)}</div>
          <div style="font-size:12px;color:var(--text-dim);margin-top:10px">
            Estate-wide control breakdown across managed and observed assets
          </div>
        </div>
        <button onclick="document.getElementById('ce32-control-modal').remove()" style="background:transparent;border:0;color:var(--text-dim);font-size:34px;cursor:pointer">×</button>
      </div>

      <div style="padding:18px 30px;display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px">
        <div class="card"><div class="card-body"><div style="font-size:12px;color:var(--text-dim)">Average Score</div><div style="font-size:28px;color:var(--teal);font-family:'JetBrains Mono'">${escapeHtml(averageScore)}</div></div></div>
        <div class="card"><div class="card-body"><div style="font-size:12px;color:var(--text-dim)">Pass</div><div style="font-size:28px;color:var(--white)">${pass}</div></div></div>
        <div class="card"><div class="card-body"><div style="font-size:12px;color:var(--text-dim)">Partial</div><div style="font-size:28px;color:var(--white)">${partial}</div></div></div>
        <div class="card"><div class="card-body"><div style="font-size:12px;color:var(--text-dim)">Fail</div><div style="font-size:28px;color:var(--white)">${fail}</div></div></div>
        <div class="card"><div class="card-body"><div style="font-size:12px;color:var(--text-dim)">Not Assessed</div><div style="font-size:28px;color:var(--white)">${notAssessed}</div></div></div>
      </div>

      <div style="padding:0 30px 18px">
        <div class="card"><div class="card-body">
          <div style="font-size:12px;color:var(--text-dim);text-transform:uppercase;margin-bottom:12px">Top Findings</div>
          ${allFindings.length ? `<ul style="margin:0;padding-left:18px;color:var(--text);line-height:1.8">${allFindings.slice(0,8).map(f => `<li>${escapeHtml(f)}</li>`).join('')}</ul>` : `<div style="color:var(--text-dim)">No findings</div>`}
        </div></div>
      </div>

      <div style="padding:0 30px 18px">
        <div class="card"><div class="card-body">
          <div style="font-size:12px;color:var(--text-dim);text-transform:uppercase;margin-bottom:12px">Remediation Guidance</div>
          ${allRemediation.length ? `<ul style="margin:0;padding-left:18px;color:var(--text);line-height:1.8">${allRemediation.slice(0,8).map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>` : `<div style="color:var(--text-dim)">No remediation guidance</div>`}
        </div></div>
      </div>

      <div style="padding:0 30px 30px">
        <div class="card"><div class="card-body" style="padding:0">
          <table class="data-table">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Source</th>
                <th>Overall</th>
                <th>Control</th>
                <th>Score</th>
                <th>Findings</th>
              </tr>
            </thead>
            <tbody>
              ${affected.length ? affected.map(a => `
                <tr>
                  <td>${escapeHtml(a.hostname || a.agent_id || 'Unknown')}</td>
                  <td>${escapeHtml(a.asset_source || 'unknown')}</td>
                  <td>${escapeHtml(a.overall || '')}</td>
                  <td>${ceStatusChip(a.status || 'NOT_ASSESSED')}</td>
                  <td>${escapeHtml(a.score ?? '')}</td>
                  <td style="max-width:560px">${escapeHtml((a.findings || []).join(' | ') || 'No specific finding')}</td>
                </tr>
              `).join('') : `<tr><td colspan="6" style="text-align:center;color:var(--text-dim)">No affected assets. Passing managed assets only.</td></tr>`}
            </tbody>
          </table>
        </div></div>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);
}

async function renderCE32Page"""

text2, count = re.subn(pattern, replacement, text, count=1, flags=re.S)

if count == 0:
    raise SystemExit("Could not find showCE32Control function block. No change made.")

path.write_text(text2, encoding="utf-8")
print(f"Patched CE v3.2 estate drilldown modal. Backup: {backup}")