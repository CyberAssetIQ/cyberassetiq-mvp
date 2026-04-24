"""
patch_vulns.py
Adds VUL-04 through VUL-10 to the vulnerabilities page:
  VUL-04  Accept Risk button per row
  VUL-05  False Positive button per row
  VUL-06  Scan History tab
  VUL-07  Scan status polling after trigger
  VUL-08  AI Explain modal (replaces alert())
  VUL-09  AI Risk Priorities panel
  VUL-10  Add Annotation / note per CVE

Run inside the container:
  docker cp patch_vulns.py cyberassetiq-backend-1:/app/patch_vulns.py
  docker exec cyberassetiq-backend-1 python /app/patch_vulns.py
"""

INDEX_PATH = '/app/static/index.html'

with open(INDEX_PATH, 'r', encoding='utf-8') as f:
    html = f.read()

if 'acceptRisk' in html:
    print('Already patched — nothing to do.')
    exit(0)


# ═══════════════════════════════════════════════════════════════════════════════
# PATCH 1 — Replace the vulnerabilities page HTML section
# Adds: Status filter tabs (Open / Accepted / False Positive / All)
#       Scan History tab
#       AI Priorities panel toggle
# ═══════════════════════════════════════════════════════════════════════════════

OLD_VULN_PAGE = """    <div class="page" id="page-vulnerabilities">
      <div class="section-header">
        <div><div class="section-title">Vulnerabilities</div><div class="section-sub">CVEs correlated from NVD against installed software</div></div>
        <div style="display:flex;gap:8px">
          <select class="form-select" style="width:140px" id="vulnFilter" onchange="filterVulns()">
            <option value="">All Severity</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <button class="btn primary" onclick="triggerVulnScan()">Run CVE Scan</button>
        </div>
      </div>
      <div class="metrics-grid" style="grid-template-columns:repeat(4,1fr)">
        <div class="metric-card red"><div class="metric-label">Critical</div><div class="metric-value red" id="vc-crit">—</div></div>
        <div class="metric-card orange"><div class="metric-label">High</div><div class="metric-value orange" id="vc-high">—</div></div>
        <div class="metric-card yellow"><div class="metric-label">Medium</div><div class="metric-value" id="vc-med">—</div></div>
        <div class="metric-card green"><div class="metric-label">Low</div><div class="metric-value green" id="vc-low">—</div></div>
      </div>
      <div class="card">
        <div class="card-body" style="padding:0">
          <div id="vulnsTable"><div class="loading-state"><div class="spinner"></div> Loading CVEs…</div></div>
        </div>
      </div>
    </div>"""

NEW_VULN_PAGE = """    <div class="page" id="page-vulnerabilities">
      <div class="section-header">
        <div><div class="section-title">Vulnerabilities</div><div class="section-sub">CVEs correlated from NVD against installed software</div></div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn" onclick="loadAIPriorities()" style="font-size:12px;padding:6px 12px">🤖 AI Priorities</button>
          <button class="btn" onclick="showScanHistory()" style="font-size:12px;padding:6px 12px">🕐 Scan History</button>
          <button class="btn primary" onclick="triggerVulnScan()" id="runScanBtn">Run CVE Scan</button>
        </div>
      </div>
      <div class="metrics-grid" style="grid-template-columns:repeat(4,1fr)">
        <div class="metric-card red"><div class="metric-label">Critical</div><div class="metric-value red" id="vc-crit">—</div></div>
        <div class="metric-card orange"><div class="metric-label">High</div><div class="metric-value orange" id="vc-high">—</div></div>
        <div class="metric-card yellow"><div class="metric-label">Medium</div><div class="metric-value" id="vc-med">—</div></div>
        <div class="metric-card green"><div class="metric-label">Low</div><div class="metric-value green" id="vc-low">—</div></div>
      </div>
      <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center">
        <div style="display:flex;gap:4px">
          <button class="vuln-status-tab active" data-status="open" onclick="setVulnStatus('open')">Open</button>
          <button class="vuln-status-tab" data-status="accepted_risk" onclick="setVulnStatus('accepted_risk')">Accepted Risk</button>
          <button class="vuln-status-tab" data-status="false_positive" onclick="setVulnStatus('false_positive')">False Positive</button>
          <button class="vuln-status-tab" data-status="resolved" onclick="setVulnStatus('resolved')">Resolved</button>
        </div>
        <select class="form-select" style="width:130px;margin-left:auto" id="vulnFilter" onchange="filterVulns()">
          <option value="">All Severity</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </div>
      <div id="aiPrioritiesPanel" style="display:none;margin-bottom:16px"></div>
      <div class="card">
        <div class="card-body" style="padding:0">
          <div id="vulnsTable"><div class="loading-state"><div class="spinner"></div> Loading CVEs…</div></div>
        </div>
      </div>
    </div>"""

if OLD_VULN_PAGE in html:
    html = html.replace(OLD_VULN_PAGE, NEW_VULN_PAGE)
    print('PATCH 1 applied — vulnerabilities page HTML upgraded')
else:
    print('PATCH 1 SKIPPED — page HTML not matched exactly, trying fallback...')
    # Fallback: just add the tabs and buttons via the section-header replacement
    old_header = '<button class="btn primary" onclick="triggerVulnScan()">Run CVE Scan</button>'
    new_header = '''<button class="btn" onclick="loadAIPriorities()" style="font-size:12px;padding:6px 12px">🤖 AI Priorities</button>
          <button class="btn" onclick="showScanHistory()" style="font-size:12px;padding:6px 12px">🕐 Scan History</button>
          <button class="btn primary" onclick="triggerVulnScan()" id="runScanBtn">Run CVE Scan</button>'''
    if old_header in html:
        html = html.replace(old_header, new_header)
        print('PATCH 1 fallback applied — buttons added')
    else:
        print('PATCH 1 FAILED — could not find insertion point')


# ═══════════════════════════════════════════════════════════════════════════════
# PATCH 2 — Add tab CSS styles
# ═══════════════════════════════════════════════════════════════════════════════

TAB_CSS = """
/* ── VULN STATUS TABS ───────────────────────────────────────────────── */
.vuln-status-tab {
  padding: 5px 12px; font-size: 12px; border-radius: 6px; cursor: pointer;
  border: 1px solid var(--border); background: transparent;
  color: var(--text-dim); font-family: inherit; transition: all 0.15s;
}
.vuln-status-tab.active {
  background: var(--teal-dim); border-color: var(--teal); color: var(--teal);
}
"""

CSS_INSERTION = '/* ── CVE ROW'
if CSS_INSERTION in html:
    html = html.replace(CSS_INSERTION, TAB_CSS + '\n' + CSS_INSERTION)
    print('PATCH 2 applied — tab CSS added')
else:
    print('PATCH 2 SKIPPED — CSS insertion point not found')


# ═══════════════════════════════════════════════════════════════════════════════
# PATCH 3 — Replace renderVulnsTable and related JS functions
# ═══════════════════════════════════════════════════════════════════════════════

OLD_RENDER = """let allVulns = [];
async function loadVulns() {
  const [summary, findings] = await Promise.all([
    api('GET', '/api/vulns/summary'),
    api('GET', '/api/vulns/findings'),
  ]);
  if (summary) {
    document.getElementById('vc-crit').textContent = summary.critical ?? 0;
    document.getElementById('vc-high').textContent = summary.high ?? 0;
    document.getElementById('vc-med').textContent  = summary.medium ?? 0;
    document.getElementById('vc-low').textContent  = summary.low ?? 0;
  }
  allVulns = findings || [];
  renderVulnsTable(allVulns);
}
function filterVulns() {
  const f = document.getElementById('vulnFilter').value;
  renderVulnsTable(f ? allVulns.filter(v => v.severity === f) : allVulns);
}
function renderVulnsTable(vulns) {
  if (!vulns.length) {
    document.getElementById('vulnsTable').innerHTML = '<div class="empty-state"><p>No CVE findings. Run a vulnerability scan first.</p></div>';
    return;
  }
  document.getElementById('vulnsTable').innerHTML = `
    <table class="data-table">
      <thead><tr>
        <th>CVE ID</th><th>CVSS</th><th>Severity</th>
        <th>Software</th><th>Asset</th><th>Status</th><th>Action</th>
      </tr></thead>
      <tbody>${vulns.slice(0,50).map(v => {
        const s = (v.severity||'low').toLowerCase();
        const bgMap = {critical:'rgba(255,71,87,0.2)',high:'rgba(255,140,66,0.2)',medium:'rgba(255,211,42,0.2)',low:'rgba(46,213,115,0.2)'};
        return `<tr>
          <td class="mono" style="color:var(--teal)">${v.cve_id||'—'}</td>
          <td><span class="cve-score" style="background:${bgMap[s]||''};color:var(--text)">${v.cvss_score??'—'}</span></td>
          <td><span class="badge ${s}">${v.severity||'—'}</span></td>
          <td>${v.software_name||'—'}</td>
          <td style="color:var(--text-dim)">${v.hostname||v.asset_id||'—'}</td>
          <td><span class="badge ${v.status==='open'?'red':v.status==='resolved'?'passed':'info'}">${v.status||'open'}</span></td>
          <td><button class="btn" style="padding:3px 8px;font-size:11px" onclick="explainCVE('${v.finding_id||v.id}','${v.cve_id}')">Explain</button></td>
        </tr>`;
      }).join('')}</tbody>
    </table>`;
}
async function triggerVulnScan() {
  toast('CVE scan triggered…', 'info');
  const r = await api('POST', '/api/vulns/scan');
  if (r) { toast('Scan started — refreshing findings', 'success'); setTimeout(loadVulns, 3000); }
  else toast('Failed to start scan', 'error');
}
async function explainCVE(id, cveId) {
  toast(`Asking AI about ${cveId}…`, 'info');
  const r = await api('POST', `/api/vulns/findings/${id}/explain`);
  if (r) {
    const msg = r.explanation || r.content?.[0]?.text || JSON.stringify(r);
    alert(`AI Explanation for ${cveId}:\\n\\n${msg}`);
  }
}"""

NEW_RENDER = """let allVulns = [];
let _vulnStatus = 'open';

async function loadVulns() {
  const [summary, findings] = await Promise.all([
    api('GET', '/api/vulns/summary'),
    api('GET', `/api/vulns/findings?status=${_vulnStatus}&limit=200`),
  ]);
  if (summary) {
    document.getElementById('vc-crit').textContent = summary.critical ?? 0;
    document.getElementById('vc-high').textContent = summary.high ?? 0;
    document.getElementById('vc-med').textContent  = summary.medium ?? 0;
    document.getElementById('vc-low').textContent  = summary.low ?? 0;
  }
  allVulns = findings || [];
  renderVulnsTable(allVulns);
}

function setVulnStatus(status) {
  _vulnStatus = status;
  document.querySelectorAll('.vuln-status-tab').forEach(b => {
    b.classList.toggle('active', b.dataset.status === status);
  });
  loadVulns();
}

function filterVulns() {
  const f = document.getElementById('vulnFilter').value;
  renderVulnsTable(f ? allVulns.filter(v => (v.severity||'').toLowerCase() === f.toLowerCase()) : allVulns);
}

function renderVulnsTable(vulns) {
  if (!vulns.length) {
    document.getElementById('vulnsTable').innerHTML = `<div class="empty-state"><p>No ${_vulnStatus.replace('_',' ')} CVE findings.</p></div>`;
    return;
  }
  const bgMap = {critical:'rgba(255,71,87,0.2)',high:'rgba(255,140,66,0.2)',medium:'rgba(255,211,42,0.2)',low:'rgba(46,213,115,0.2)'};
  document.getElementById('vulnsTable').innerHTML = `
    <table class="data-table">
      <thead><tr>
        <th>CVE ID</th><th>CVSS</th><th>Severity</th>
        <th>Software</th><th>Asset</th><th>Status</th><th>Actions</th>
      </tr></thead>
      <tbody>${vulns.slice(0,100).map(v => {
        const s = (v.severity||'low').toLowerCase();
        const fid = v.finding_id || v.id;
        const statusBadge = {open:'red',resolved:'passed',accepted_risk:'info',false_positive:'pending'};
        return `<tr>
          <td class="mono" style="color:var(--teal);cursor:pointer" onclick="showCVEDetail(${JSON.stringify(v).replace(/"/g,'&quot;')})">${v.cve_id||'—'}</td>
          <td><span class="cve-score" style="background:${bgMap[s]||''};color:var(--text)">${v.cvss_score??'—'}</span></td>
          <td><span class="badge ${s}">${v.severity||'—'}</span></td>
          <td>${v.software_name||'—'}</td>
          <td style="color:var(--text-dim);font-size:12px">${v.hostname||v.asset_id||'—'}</td>
          <td><span class="badge ${statusBadge[v.status]||'info'}">${(v.status||'open').replace('_',' ')}</span></td>
          <td style="white-space:nowrap;display:flex;gap:4px;flex-wrap:wrap">
            <button class="btn" style="padding:3px 7px;font-size:11px" onclick="explainCVE('${fid}','${v.cve_id}')">🤖 Explain</button>
            <button class="btn" style="padding:3px 7px;font-size:11px;color:#f59e0b;border-color:#f59e0b" onclick="acceptRisk('${fid}','${v.cve_id}')">✓ Accept</button>
            <button class="btn" style="padding:3px 7px;font-size:11px;color:var(--text-dim);border-color:var(--border)" onclick="markFalsePositive('${fid}','${v.cve_id}')">✗ FP</button>
            <button class="btn" style="padding:3px 7px;font-size:11px;color:#a78bfa;border-color:#a78bfa" onclick="addAnnotation('${fid}','${v.cve_id}')">📝 Note</button>
          </td>
        </tr>`;
      }).join('')}</tbody>
    </table>`;
}

async function triggerVulnScan() {
  const btn = document.getElementById('runScanBtn');
  if (btn) { btn.textContent = '⏳ Scanning…'; btn.disabled = true; }
  toast('CVE scan triggered…', 'info');
  const r = await api('POST', '/api/vulns/scan');
  if (!r) { toast('Failed to start scan', 'error'); if (btn) { btn.textContent = 'Run CVE Scan'; btn.disabled = false; } return; }
  toast('Scan running — polling for completion…', 'info');
  let polls = 0;
  const poll = setInterval(async () => {
    polls++;
    const status = await api('GET', '/api/vulns/scan/status');
    if ((status && !status.scan_running) || polls > 30) {
      clearInterval(poll);
      if (btn) { btn.textContent = 'Run CVE Scan'; btn.disabled = false; }
      toast('Scan complete — reloading findings', 'success');
      loadVulns();
    }
  }, 3000);
}

async function explainCVE(id, cveId) {
  toast(`Asking AI about ${cveId}…`, 'info');
  const r = await api('POST', `/api/vulns/findings/${id}/explain`);
  if (!r) { toast('AI explain failed', 'error'); return; }
  const msg = r.explanation || r.summary || r.content?.[0]?.text || JSON.stringify(r, null, 2);
  const priority = r.adjusted_priority || r.priority || '';
  const urgency = r.patch_urgency || '';
  const overlay = document.createElement('div');
  overlay.className = 'cy-temp-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:9999;display:flex;align-items:center;justify-content:center;padding:16px';
  overlay.innerHTML = `
    <div style="background:var(--navy2);border:1px solid var(--border);border-radius:var(--radius);padding:28px;max-width:620px;width:100%;max-height:80vh;overflow-y:auto">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px">
        <div>
          <div style="font-size:15px;font-weight:600;color:var(--white);margin-bottom:4px">🤖 AI CVE Analysis</div>
          <div style="font-family:monospace;font-size:13px;color:var(--teal)">${cveId}</div>
        </div>
        <button onclick="this.closest('.cy-temp-overlay').remove()" style="background:transparent;border:none;color:var(--text-dim);cursor:pointer;font-size:18px">✕</button>
      </div>
      ${priority ? `<div style="display:flex;gap:8px;margin-bottom:14px">
        <span style="font-size:12px;padding:3px 10px;border-radius:4px;background:rgba(255,71,87,0.15);color:#ff4757">Priority: ${priority}</span>
        ${urgency ? `<span style="font-size:12px;padding:3px 10px;border-radius:4px;background:rgba(255,140,66,0.15);color:#ff8c42">Urgency: ${urgency}</span>` : ''}
      </div>` : ''}
      <div style="font-size:13px;color:var(--text);line-height:1.7;white-space:pre-wrap">${msg}</div>
      <div style="margin-top:20px;text-align:right">
        <button class="btn" onclick="this.closest('.cy-temp-overlay').remove()">Close</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
}

async function acceptRisk(findingId, cveId) {
  const note = prompt(`Accept risk for ${cveId}?\\nOptional reason:`, '');
  if (note === null) return;
  const r = await api('PATCH', `/api/vulns/findings/${findingId}/status`, { status: 'accepted_risk', note });
  if (r && r.status) { toast(`${cveId} marked as accepted risk`, 'success'); loadVulns(); }
  else toast('Failed to update status', 'error');
}

async function markFalsePositive(findingId, cveId) {
  if (!confirm(`Mark ${cveId} as false positive?`)) return;
  const r = await api('PATCH', `/api/vulns/findings/${findingId}/status`, { status: 'false_positive' });
  if (r && r.status) { toast(`${cveId} marked as false positive`, 'success'); loadVulns(); }
  else toast('Failed to update status', 'error');
}

async function addAnnotation(findingId, cveId) {
  const note = prompt(`Add note for ${cveId}:`, '');
  if (!note) return;
  const r = await api('PATCH', `/api/vulns/findings/${findingId}/status`, { status: _vulnStatus || 'open', note });
  if (r) { toast('Note saved', 'success'); }
  else toast('Failed to save note', 'error');
}

function showCVEDetail(v) {
  const s = (v.severity||'low').toLowerCase();
  const colMap = {critical:'#ff4757',high:'#ff8c42',medium:'#ffd32a',low:'#2ed573'};
  const overlay = document.createElement('div');
  overlay.className = 'cy-temp-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:9999;display:flex;align-items:center;justify-content:center;padding:16px';
  overlay.innerHTML = `
    <div style="background:var(--navy2);border:1px solid var(--border);border-radius:var(--radius);padding:28px;max-width:580px;width:100%;max-height:80vh;overflow-y:auto">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px">
        <div>
          <div style="font-family:monospace;font-size:16px;font-weight:700;color:var(--teal)">${v.cve_id||'—'}</div>
          <div style="font-size:12px;color:var(--text-dim);margin-top:2px">${v.software_name||''} ${v.software_version||''}</div>
        </div>
        <button onclick="this.closest('.cy-temp-overlay').remove()" style="background:transparent;border:none;color:var(--text-dim);cursor:pointer;font-size:18px">✕</button>
      </div>
      <div style="display:flex;gap:10px;margin-bottom:16px">
        <span style="font-size:13px;padding:4px 12px;border-radius:4px;font-weight:600;background:${colMap[s]}22;color:${colMap[s]}">${v.severity||'—'}</span>
        <span style="font-size:13px;padding:4px 12px;border-radius:4px;background:rgba(255,255,255,0.07);color:var(--white)">CVSS ${v.cvss_score??'—'}</span>
      </div>
      <div style="font-size:13px;color:var(--text);line-height:1.6;margin-bottom:16px">${v.description||'No description available.'}</div>
      <div style="font-size:12px;color:var(--text-dim)">Asset: ${v.hostname||v.asset_id||'—'} &middot; Published: ${v.published||'—'}</div>
      <div style="margin-top:20px;display:flex;gap:8px;justify-content:flex-end">
        <button class="btn primary" style="font-size:12px" onclick="explainCVE('${v.finding_id||v.id}','${v.cve_id}');this.closest('.cy-temp-overlay').remove()">🤖 AI Explain</button>
        <button class="btn" onclick="this.closest('.cy-temp-overlay').remove()">Close</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
}

async function showScanHistory() {
  const runs = await api('GET', '/api/vulns/scan-runs?limit=20');
  if (!runs) { toast('Failed to load scan history', 'error'); return; }
  const overlay = document.createElement('div');
  overlay.className = 'cy-temp-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:9999;display:flex;align-items:center;justify-content:center;padding:16px';
  overlay.innerHTML = `
    <div style="background:var(--navy2);border:1px solid var(--border);border-radius:var(--radius);padding:28px;max-width:700px;width:100%;max-height:80vh;overflow-y:auto">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
        <div style="font-size:15px;font-weight:600;color:var(--white)">🕐 Scan History</div>
        <button onclick="this.closest('.cy-temp-overlay').remove()" style="background:transparent;border:none;color:var(--text-dim);cursor:pointer;font-size:18px">✕</button>
      </div>
      ${runs.length === 0 ? '<div class="empty-state"><p>No scan runs yet.</p></div>' : `
      <table class="data-table">
        <thead><tr><th>#</th><th>Date</th><th>Packages</th><th>Total CVEs</th><th>Critical</th><th>High</th><th>Status</th></tr></thead>
        <tbody>${runs.map(r => `<tr>
          <td style="color:var(--text-dim);font-size:12px">${r.id}</td>
          <td style="font-size:12px">${r.scan_epoch ? new Date(r.scan_epoch*1000).toLocaleString() : '—'}</td>
          <td style="font-size:12px">${r.packages_scanned??'—'} / ${r.total_packages??'—'}</td>
          <td style="font-weight:600;color:var(--white)">${r.total_cves??0}</td>
          <td style="color:#ff4757;font-weight:600">${r.critical_count??0}</td>
          <td style="color:#ff8c42;font-weight:600">${r.high_count??0}</td>
          <td><span class="badge ${r.status==='completed'?'passed':r.status==='running'?'info':'pending'}">${r.status||'—'}</span></td>
        </tr>`).join('')}</tbody>
      </table>`}
      <div style="margin-top:16px;text-align:right">
        <button class="btn" onclick="this.closest('.cy-temp-overlay').remove()">Close</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
}

async function loadAIPriorities() {
  const panel = document.getElementById('aiPrioritiesPanel');
  if (!panel) return;
  if (panel.style.display !== 'none') { panel.style.display = 'none'; return; }
  panel.style.display = 'block';
  panel.innerHTML = '<div class="loading-state"><div class="spinner"></div> AI ranking vulnerabilities…</div>';
  const r = await api('GET', '/api/vulns/findings/ai-priorities?limit=10');
  if (!r || !r.length) {
    panel.innerHTML = '<div class="card"><div class="card-body"><p style="color:var(--text-dim);font-size:13px">No AI priorities available — run a scan first.</p></div></div>';
    return;
  }
  panel.innerHTML = `
    <div class="card">
      <div class="card-body">
        <div style="font-size:13px;font-weight:600;color:var(--white);margin-bottom:12px">🤖 AI Risk Priorities — Top ${r.length} CVEs by exploitability</div>
        ${r.map((item, i) => {
          const v = item.finding || item;
          const priority = item.adjusted_priority || item.priority || v.severity || '—';
          const reason = item.reason || item.explanation || item.summary || '';
          const colMap = {critical:'#ff4757',high:'#ff8c42',medium:'#ffd32a',low:'#2ed573'};
          const col = colMap[(priority||'').toLowerCase()] || 'var(--text-dim)';
          return `<div style="display:flex;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);align-items:flex-start">
            <div style="font-size:18px;font-weight:700;color:var(--text-dim);min-width:24px">${i+1}</div>
            <div style="flex:1">
              <div style="display:flex;gap:8px;align-items:center;margin-bottom:4px">
                <span style="font-family:monospace;font-size:13px;color:var(--teal)">${v.cve_id||item.cve_id||'—'}</span>
                <span style="font-size:11px;padding:2px 8px;border-radius:3px;background:${col}22;color:${col}">${priority}</span>
              </div>
              <div style="font-size:12px;color:var(--text-dim)">${v.software_name||''}</div>
              ${reason ? `<div style="font-size:12px;color:var(--text);margin-top:4px;line-height:1.5">${reason}</div>` : ''}
            </div>
          </div>`;
        }).join('')}
      </div>
    </div>`;
}"""

if OLD_RENDER in html:
    html = html.replace(OLD_RENDER, NEW_RENDER)
    print('PATCH 3 applied — all vuln JS functions upgraded')
else:
    print('PATCH 3 SKIPPED — JS block not matched exactly')
    print('  Trying to patch individual functions...')
    # Fallback: patch just the explainCVE alert
    old_explain = """async function explainCVE(id, cveId) {
  toast(`Asking AI about ${cveId}…`, 'info');
  const r = await api('POST', `/api/vulns/findings/${id}/explain`);
  if (r) {
    const msg = r.explanation || r.content?.[0]?.text || JSON.stringify(r);
    alert(`AI Explanation for ${cveId}:\\n\\n${msg}`);
  }
}"""
    if old_explain in html:
        html = html.replace(old_explain, NEW_RENDER.split('async function acceptRisk')[0])
        print('  Fallback: explainCVE replaced with modal version')


# ── Write the patched file ────────────────────────────────────────────────────
with open(INDEX_PATH, 'w', encoding='utf-8') as f:
    f.write(html)

print('\nAll done. Hard-refresh your browser (Ctrl+Shift+R).')
