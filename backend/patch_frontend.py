"""
patch_frontend.py
Run inside the Docker container:
  docker cp patch_frontend.py cyberassetiq-backend-1:/app/patch_frontend.py
  docker exec cyberassetiq-backend-1 python /app/patch_frontend.py

This patches /app/../index.html (one level up from /app).
Adjust INDEX_PATH below if your index.html is elsewhere.
"""

INDEX_PATH = '/app/static/index.html'

with open(INDEX_PATH, 'r', encoding='utf-8') as f:
    html = f.read()

# ── GUARD: don't double-patch ─────────────────────────────────────────────────
if 'quarantineAgent' in html:
    print('Already patched — nothing to do.')
    exit(0)


# ═══════════════════════════════════════════════════════════════════════════════
# PATCH 1 — Replace the Agents tab table in renderAdminPage
# Add: header row with "+ Enrol Agent" and "Generate ID" buttons
# Add: Actions column with Quarantine, Force Check-in, Rotate Key, Reassign Policy
# ═══════════════════════════════════════════════════════════════════════════════

OLD_AGENTS_BLOCK = """  // Render Agents
  const agentsEl = document.getElementById('adm-agents');
  const agentsList = Array.isArray(agents) ? agents : (agents && agents.agents ? agents.agents : []);
  agentsEl.innerHTML = `
    <div style="margin-bottom:12px;font-size:13px;color:var(--text-dim)">${agentsList.length} enrolled agent(s)</div>
    <div class="card"><div class="card-body" style="padding:0">
    <table class="data-table">
      <thead><tr><th>Agent ID</th><th>Hostname</th><th>OS</th><th>Status</th><th>Health</th><th>Last Seen</th></tr></thead>
      <tbody>${agentsList.map(a => `<tr>
        <td style="font-family:monospace;font-size:11px;color:var(--text-dim)">${a.agent_id||'—'}</td>
        <td style="font-weight:600;color:var(--white)">${a.hostname||'—'}</td>
        <td style="font-size:12px">${a.os_family||'—'}</td>
        <td><span class="badge ${a.status==='active'?'active':'offline'}">${a.status||'unknown'}</span></td>
        <td><span class="badge ${a.health==='active'?'active':'pending'}">${a.health||'unknown'}</span></td>
        <td style="color:var(--text-dim);font-size:12px">${a.last_seen_epoch ? timeAgo(a.last_seen_epoch*1000) : '—'}</td>
      </tr>`).join('')}</tbody>
    </table></div></div>`;"""

NEW_AGENTS_BLOCK = """  // Render Agents
  const agentsEl = document.getElementById('adm-agents');
  const agentsList = Array.isArray(agents) ? agents : (agents && agents.agents ? agents.agents : []);
  agentsEl.innerHTML = `
    <div style="margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
      <div style="font-size:13px;color:var(--text-dim)">${agentsList.length} enrolled agent(s)</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button onclick="generateAgentId()" style="
          padding:6px 12px;font-size:12px;border-radius:6px;border:1px solid var(--teal);
          background:transparent;color:var(--teal);cursor:pointer;font-family:inherit">
          ⚡ Generate ID
        </button>
        <button onclick="openEnrolModal()" style="
          padding:6px 14px;font-size:12px;border-radius:6px;border:none;
          background:var(--teal);color:#0D1E31;cursor:pointer;font-weight:600;font-family:inherit">
          + Enrol Agent
        </button>
      </div>
    </div>
    <div class="card"><div class="card-body" style="padding:0">
    <table class="data-table">
      <thead><tr><th>Agent ID</th><th>Hostname</th><th>OS</th><th>Status</th><th>Health</th><th>Last Seen</th><th>Actions</th></tr></thead>
      <tbody>${agentsList.map(a => `<tr>
        <td style="font-family:monospace;font-size:11px;color:var(--text-dim)">${a.agent_id||'—'}</td>
        <td style="font-weight:600;color:var(--white)">${a.hostname||'—'}</td>
        <td style="font-size:12px">${a.os_family||'—'}</td>
        <td><span class="badge ${a.status==='active'?'active':'offline'}">${a.status||'unknown'}</span></td>
        <td><span class="badge ${a.health==='active'?'active':'pending'}">${a.health||'unknown'}</span></td>
        <td style="color:var(--text-dim);font-size:12px">${a.last_seen_epoch ? timeAgo(a.last_seen_epoch*1000) : '—'}</td>
        <td style="white-space:nowrap">
          <button onclick="quarantineAgent('${a.agent_id}')" title="Quarantine" style="
            padding:3px 7px;font-size:11px;border-radius:4px;border:1px solid #ef4444;
            background:transparent;color:#ef4444;cursor:pointer;margin-right:3px">
            🔒 Quarantine
          </button>
          <button onclick="forceCheckin('${a.agent_id}')" title="Force Check-in" style="
            padding:3px 7px;font-size:11px;border-radius:4px;border:1px solid var(--teal);
            background:transparent;color:var(--teal);cursor:pointer;margin-right:3px">
            ↻ Check-in
          </button>
          <button onclick="rotateAgentKey('${a.agent_id}')" title="Rotate Trust Key" style="
            padding:3px 7px;font-size:11px;border-radius:4px;border:1px solid #f59e0b;
            background:transparent;color:#f59e0b;cursor:pointer;margin-right:3px">
            🔑 Rotate Key
          </button>
          <button onclick="openPolicyModal('${a.agent_id}')" title="Reassign Policy" style="
            padding:3px 7px;font-size:11px;border-radius:4px;border:1px solid #a78bfa;
            background:transparent;color:#a78bfa;cursor:pointer">
            ⚙ Policy
          </button>
        </td>
      </tr>`).join('')}</tbody>
    </table></div></div>`;"""

if OLD_AGENTS_BLOCK in html:
    html = html.replace(OLD_AGENTS_BLOCK, NEW_AGENTS_BLOCK)
    print('PATCH 1 applied — Agents table upgraded with action buttons')
else:
    print('PATCH 1 SKIPPED — agents block not found (may already be patched or HTML changed)')


# ═══════════════════════════════════════════════════════════════════════════════
# PATCH 2 — Inject new JS functions before // ── END ADMIN ACTIONS ──
# Functions: quarantineAgent, forceCheckin, rotateAgentKey,
#            openPolicyModal, openEnrolModal, generateAgentId
# ═══════════════════════════════════════════════════════════════════════════════

NEW_FUNCTIONS = """
// ── AGENT ACTION FUNCTIONS ────────────────────────────────────────────────────

async function quarantineAgent(agentId) {
  if (!confirm(`Quarantine agent ${agentId}?\\n\\nThis will queue an isolation command. The agent will cut network access on its next poll.`)) return;
  const res = await api('POST', `/api/agents/${agentId}/quarantine`);
  if (res && res.ok) {
    toast(`Isolation command queued (${res.command_id})`, 'success');
  } else {
    toast('Quarantine failed — check permissions', 'error');
  }
}

async function forceCheckin(agentId) {
  const res = await api('POST', `/api/agents/${agentId}/force-checkin`);
  if (res && res.ok) {
    toast(`Force check-in queued (${res.command_id})`, 'success');
  } else {
    toast('Force check-in failed', 'error');
  }
}

async function rotateAgentKey(agentId) {
  if (!confirm(`Rotate trust key for agent ${agentId}?\\n\\nThe old key is invalidated immediately. You must push the new key to the agent before it next heartbeats.`)) return;
  const res = await api('POST', `/api/admin/agents/${agentId}/rotate-key`);
  if (res && res.new_trust_key) {
    const overlay = document.createElement('div');
    overlay.className = 'cy-temp-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;display:flex;align-items:center;justify-content:center';
    overlay.innerHTML = `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:32px;max-width:540px;width:90%">
        <div style="font-size:15px;font-weight:600;color:var(--white);margin-bottom:6px">🔑 Trust Key Rotated</div>
        <div style="font-size:12px;color:var(--text-dim);margin-bottom:6px">Agent: <span style="color:var(--teal);font-family:monospace">${agentId}</span></div>
        <div style="font-size:12px;color:#ef4444;margin-bottom:14px">⚠ Save this key now — it will <strong>never be shown again</strong>. Set CYBERASSETIQ_TRUST_KEY on the agent.</div>
        <div style="background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:6px;padding:12px;font-family:monospace;font-size:12px;color:var(--teal);word-break:break-all;margin-bottom:16px">${res.new_trust_key}</div>
        <div style="display:flex;gap:8px">
          <button class="btn primary" onclick="copyToClipboard('${res.new_trust_key}')">Copy Key</button>
          <button class="btn" onclick="closeOverlayAndRefresh(this)">Close</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
  } else {
    toast('Key rotation failed — ' + (res && res.detail ? res.detail : 'check permissions'), 'error');
  }
}

async function generateAgentId() {
  const res = await api('POST', '/api/admin/agents/generate-id');
  if (res && res.agent_id) {
    const overlay = document.createElement('div');
    overlay.className = 'cy-temp-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;display:flex;align-items:center;justify-content:center';
    overlay.innerHTML = `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:32px;max-width:520px;width:90%">
        <div style="font-size:15px;font-weight:600;color:var(--white);margin-bottom:6px">⚡ Agent ID Generated</div>
        <div style="font-size:12px;color:var(--text-dim);margin-bottom:14px">Use this ID when pre-registering a device before enrolment.</div>
        <div style="background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:6px;padding:12px;font-family:monospace;font-size:13px;color:var(--teal);word-break:break-all;margin-bottom:16px">${res.agent_id}</div>
        <div style="display:flex;gap:8px">
          <button class="btn primary" onclick="copyToClipboard('${res.agent_id}')">Copy ID</button>
          <button class="btn" onclick="this.closest('.cy-temp-overlay').remove()">Close</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
  } else {
    toast('Failed to generate agent ID', 'error');
  }
}

function openEnrolModal() {
  const overlay = document.createElement('div');
  overlay.className = 'cy-temp-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;display:flex;align-items:center;justify-content:center';
  overlay.innerHTML = `
    <div style="background:var(--navy2);border:1px solid var(--border);border-radius:var(--radius);padding:32px;max-width:520px;width:90%">
      <div style="font-size:15px;font-weight:600;color:var(--white);margin-bottom:4px">+ Enrol New Agent</div>
      <div style="font-size:12px;color:var(--text-dim);margin-bottom:20px">Generate an enrollment token and download instructions for a new device.</div>
      <div style="margin-bottom:14px">
        <label style="font-size:12px;color:var(--text-dim);display:block;margin-bottom:4px">Token Label</label>
        <input id="enrol-label" type="text" value="New agent" placeholder="e.g. Office laptop - John"
          style="width:100%;padding:8px 10px;background:rgba(0,0,0,.3);border:1px solid var(--border);
                 border-radius:6px;color:var(--white);font-size:13px;outline:none;font-family:inherit">
      </div>
      <div style="margin-bottom:20px">
        <label style="font-size:12px;color:var(--text-dim);display:block;margin-bottom:4px">OS Target</label>
        <select id="enrol-os" style="width:100%;padding:8px 10px;background:rgba(0,0,0,.3);border:1px solid var(--border);
                 border-radius:6px;color:var(--white);font-size:13px;outline:none;font-family:inherit">
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
          <option value="macos">macOS</option>
        </select>
      </div>
      <div style="display:flex;gap:8px">
        <button onclick="submitEnrolment(this)" class="btn primary" style="flex:1">Generate Token</button>
        <button onclick="this.closest('.cy-temp-overlay').remove()" class="btn" style="flex:1">Cancel</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
}

async function submitEnrolment(btn) {
  const label = document.getElementById('enrol-label').value || 'New agent';
  const res = await api('POST', '/api/admin/enrollment-tokens', { label });
  const tokenVal = res && (res.token || res.token_value);
  if (!tokenVal) { toast('Failed to create enrollment token', 'error'); return; }
  btn.closest('.cy-temp-overlay').remove();
  const overlay = document.createElement('div');
  overlay.className = 'cy-temp-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;display:flex;align-items:center;justify-content:center';
  overlay.innerHTML = `
    <div style="background:var(--navy2);border:1px solid var(--border);border-radius:var(--radius);padding:32px;max-width:540px;width:90%">
      <div style="font-size:15px;font-weight:600;color:var(--white);margin-bottom:6px">✅ Enrollment Token Ready</div>
      <div style="font-size:12px;color:#ef4444;margin-bottom:14px">⚠ Save this token — it will <strong>never be shown again</strong>.</div>
      <div style="background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:6px;padding:12px;font-family:monospace;font-size:12px;color:var(--teal);word-break:break-all;margin-bottom:8px">${tokenVal}</div>
      <div style="font-size:12px;color:var(--text-dim);margin-bottom:16px">
        Set this on the agent before running the installer:<br>
        <code style="color:var(--teal)">CYBERASSETIQ_ENROLLMENT_TOKEN=${tokenVal}</code>
      </div>
      <div style="display:flex;gap:8px">
        <button class="btn primary" onclick="copyToClipboard('${tokenVal}')">Copy Token</button>
        <button class="btn" onclick="closeOverlayAndRefresh(this)">Close & Refresh</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
}

function openPolicyModal(agentId) {
  const defaultPolicy = JSON.stringify({
    collection: { software: true, security: true, network: true, secret_scan: false },
    updater: { enabled: false }
  }, null, 2);
  const overlay = document.createElement('div');
  overlay.className = 'cy-temp-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;display:flex;align-items:center;justify-content:center';
  overlay.innerHTML = `
    <div style="background:var(--navy2);border:1px solid var(--border);border-radius:var(--radius);padding:32px;max-width:540px;width:90%">
      <div style="font-size:15px;font-weight:600;color:var(--white);margin-bottom:4px">⚙ Reassign Policy</div>
      <div style="font-size:12px;color:var(--text-dim);margin-bottom:16px">Agent: <span style="color:var(--teal);font-family:monospace">${agentId}</span></div>
      <label style="font-size:12px;color:var(--text-dim);display:block;margin-bottom:6px">Policy JSON</label>
      <textarea id="policy-json-input" rows="8" style="width:100%;padding:10px;background:rgba(0,0,0,.3);
        border:1px solid var(--border);border-radius:6px;color:var(--white);font-family:monospace;
        font-size:12px;outline:none;resize:vertical;margin-bottom:16px">${defaultPolicy}</textarea>
      <div style="display:flex;gap:8px">
        <button onclick="submitPolicy('${agentId}', this)" class="btn primary" style="flex:1">Apply Policy</button>
        <button onclick="this.closest('.cy-temp-overlay').remove()" class="btn" style="flex:1">Cancel</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
}

async function submitPolicy(agentId, btn) {
  let policy;
  try {
    policy = JSON.parse(document.getElementById('policy-json-input').value);
  } catch(e) {
    toast('Invalid JSON — fix the policy and try again', 'error');
    return;
  }
  const res = await api('PATCH', `/api/admin/agents/${agentId}/policy`, { policy });
  if (res && res.ok) {
    toast('Policy updated — agent will apply on next poll', 'success');
    btn.closest('.cy-temp-overlay').remove();
  } else {
    toast('Policy update failed — ' + (res && res.detail ? res.detail : 'check permissions'), 'error');
  }
}

// ── END AGENT ACTION FUNCTIONS ────────────────────────────────────────────────
"""

INSERTION_POINT = '// ── END ADMIN ACTIONS ─────────────────────────────────────────────────────────'

if INSERTION_POINT in html:
    html = html.replace(INSERTION_POINT, NEW_FUNCTIONS + '\n' + INSERTION_POINT)
    print('PATCH 2 applied — agent action functions injected')
else:
    print('PATCH 2 SKIPPED — insertion point not found')


# ── Write the patched file ────────────────────────────────────────────────────
with open(INDEX_PATH, 'w', encoding='utf-8') as f:
    f.write(html)

print('\nAll done. Hard-refresh your browser (Ctrl+Shift+R) to see the changes.')
