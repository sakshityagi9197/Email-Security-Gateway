// Simple SPA using hash routes and fetch wrapper with token refresh
const API_BASE = localStorage.getItem('API_BASE') || 'http://127.0.0.1:8000';

const state = {
  accessToken: localStorage.getItem('accessToken') || null,
  refreshToken: localStorage.getItem('refreshToken') || null,
  user: JSON.parse(localStorage.getItem('user') || 'null'),
  roles: JSON.parse(localStorage.getItem('roles') || '[]'),
  notifyTimer: null,
  lastSeenCreatedAt: localStorage.getItem('lastSeenCreatedAt') || null,
};

function setAuth({ accessToken, refreshToken, user, roles }) {
  if (accessToken !== undefined) {
    state.accessToken = accessToken;
    if (accessToken) localStorage.setItem('accessToken', accessToken); else localStorage.removeItem('accessToken');
  }
  if (refreshToken !== undefined) {
    state.refreshToken = refreshToken;
    if (refreshToken) localStorage.setItem('refreshToken', refreshToken); else localStorage.removeItem('refreshToken');
  }
  if (user !== undefined) {
    state.user = user;
    if (user) localStorage.setItem('user', JSON.stringify(user)); else localStorage.removeItem('user');
  }
  if (roles !== undefined) {
    state.roles = roles || [];
    localStorage.setItem('roles', JSON.stringify(state.roles));
  }
  updateNavbar();
}

function hasRole(...roles) {
  if (!roles || roles.length === 0) return !!state.accessToken;
  return state.roles.some(r => roles.includes(r));
}

// Stacked toast notifications
let __toastTimer = null; // kept for backward-compat but unused for stacked items
function _ensureToastContainer() {
  let c = document.getElementById('toastStack');
  if (!c) {
    c = document.createElement('div');
    c.id = 'toastStack';
    c.style.position = 'fixed';
    c.style.top = '12px';
    c.style.right = '12px';
    c.style.zIndex = '99999';
    c.style.display = 'flex';
    c.style.flexDirection = 'column';
    c.style.gap = '8px';
    document.body.appendChild(c);
  }
  return c;
}
function toast(msg, opts = {}) {
  const c = _ensureToastContainer();
  const t = document.createElement('div');
  t.className = 'toast-item';
  // Inline minimal styling in case CSS not present
  t.style.background = 'rgba(30,30,30,0.95)';
  t.style.color = '#fff';
  t.style.padding = '10px 14px';
  t.style.borderRadius = '6px';
  t.style.boxShadow = '0 2px 8px rgba(0,0,0,0.25)';
  t.style.maxWidth = '420px';
  t.style.fontFamily = 'system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif';
  t.style.fontSize = '14px';
  t.style.lineHeight = '1.3';
  t.textContent = String(msg ?? '');
  // Close on click
  t.addEventListener('click', () => { if (t.parentNode) t.parentNode.removeChild(t); });
  // Insert on top
  if (c.firstChild) c.insertBefore(t, c.firstChild); else c.appendChild(t);
  const persist = !!opts.persist || (opts.duration === 0);
  const dur = typeof opts.duration === 'number' ? opts.duration : 2500;
  if (!persist) {
    setTimeout(() => { if (t.parentNode) t.parentNode.removeChild(t); }, Math.max(0, dur));
  }
}
function toastHide() {
  // Remove the most recent toast, if any
  const c = document.getElementById('toastStack');
  if (!c || !c.firstChild) return;
  c.removeChild(c.firstChild);
}

async function apiFetch(path, opts = {}, tryRefresh = true) {
  const headers = Object.assign({}, opts.headers || {}, { 'Content-Type': 'application/json' });
  if (state.accessToken) headers['Authorization'] = `Bearer ${state.accessToken}`;
  const res = await fetch(`${API_BASE}${path}`, { ...opts, headers });
  if (res.status === 401 && tryRefresh && state.refreshToken) {
    // attempt refresh
    const r = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: state.refreshToken })
    });
    if (r.ok) {
      const j = await r.json();
      setAuth({ accessToken: j.access_token });
      return apiFetch(path, opts, false);
    } else {
      // logout
      setAuth({ accessToken: null, refreshToken: null, user: null, roles: [] });
      location.hash = '#/login';
      throw new Error('Unauthorized');
    }
  }
  return res;
}

function updateNavbar() {
  const nav = document.getElementById('navbar');
  const badge = document.getElementById('userBadge');
  if (state.accessToken) {
    nav.classList.remove('hidden');
    badge.textContent = state.user?.username || 'user';
    badge.title = `Roles: ${state.roles.join(', ') || 'none'}`;
    startLiveNotifications();
  } else {
    nav.classList.add('hidden');
    stopLiveNotifications();
  }
}

document.getElementById('logoutBtn').addEventListener('click', async () => {
  try {
    if (state.refreshToken) {
      await apiFetch('/auth/logout', { method: 'POST', body: JSON.stringify({ refresh_token: state.refreshToken }) });
    }
  } catch {}
  setAuth({ accessToken: null, refreshToken: null, user: null, roles: [] });
  state.lastSeenCreatedAt = null;
  localStorage.removeItem('lastSeenCreatedAt');
  location.hash = '#/login';
});

document.getElementById('refreshBtn').addEventListener('click', async () => {
  try {
    await apiFetch('/sync', { method: 'POST' });
    toast('Synced');
    // Re-render current route
    router();
  } catch (e) { toast('Sync failed'); }
});

// Upload EML: nav button opens an off-screen file input
async function handleEmlUpload(file) {
  if (!file) return;
  if (!state.accessToken) { toast('Please login'); return; }
  if (!file.name.toLowerCase().endsWith('.eml')) { toast('Select a .eml file'); return; }
  try {
    toast('Uploading EML…');
    const fd = new FormData();
    fd.append('file', file, file.name);
    const res = await fetch(`${API_BASE}/analyze/upload`, {
      method: 'POST',
      headers: state.accessToken ? { 'Authorization': `Bearer ${state.accessToken}` } : {},
      body: fd,
    });
    if (!res.ok) {
      const msg = res.status === 403 ? 'Not authorized to upload' : 'Upload failed';
      toast(msg);
      return;
    }
    const result = await res.json();
    const subj = (result.email && result.email.subject) || '(no subject)';
    const decision = result.final_decision || 'N/A';
    const score = (result.policy && result.policy.threat_score) ?? '—';
    toast(`Analyzed: ${subj} — ${decision} (score: ${score})`);
    router();
  } catch (err) {
    console.error(err);
    toast('Upload failed');
  }
}

async function handleEmlUploads(fileList) {
  const files = Array.from(fileList || []).filter(f => f && f.name && f.name.toLowerCase().endsWith('.eml'));
  if (!files.length) { toast('Select .eml files'); return; }
  if (!state.accessToken) { toast('Please login'); return; }
  const max = Math.min(10, files.length);
  let success = 0;
  for (let i = 0; i < max; i++) {
    const file = files[i];
    try {
      toast(`Uploading ${i+1}/${max}: ${file.name}`, { persist: true });
      const fd = new FormData();
      fd.append('file', file, file.name);
      const res = await fetch(`${API_BASE}/analyze/upload`, {
        method: 'POST',
        headers: state.accessToken ? { 'Authorization': `Bearer ${state.accessToken}` } : {},
        body: fd,
      });
      if (!res.ok) continue;
      success++;
    } catch {}
  }
  toast(`Analyzed ${success}/${max} file(s)`, { duration: 4000 });
  router();
}

document.getElementById('uploadEmlBtn').addEventListener('click', () => {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.eml,message/rfc822';
  input.multiple = true; // allow up to 10 files
  input.style.position = 'fixed';
  input.style.left = '-9999px';
  document.body.appendChild(input);
  input.addEventListener('change', async (e) => {
    const files = e.target.files;
    document.body.removeChild(input);
    await handleEmlUploads(files);
  }, { once: true });
  input.click();
});

// Views
const app = document.getElementById('app');

function viewLanding() {
  app.innerHTML = `
    <div class="panel" style="text-align:center; padding:48px;">
      <h1>Email Security Gateway</h1>
      <p class="muted">Secure. Monitor. Act.</p>
      <div style="margin-top:16px;">
        <a href="#/login" class="btn">Login</a>
      </div>
    </div>
  `;
}

function viewLogin() {
  app.innerHTML = `
    <div class="panel" style="max-width:420px; margin:40px auto;">
      <h2>Login</h2>
      <div class="field"><label>Username</label><input class="input" id="u" /></div>
      <div class="field"><label>Password</label><input type="password" class="input" id="p" /></div>
      <div class="toolbar">
        <div class="spacer"></div>
        <button id="loginBtn" class="btn btn-ok">Sign In</button>
      </div>
      <div id="err" class="muted"></div>
    </div>
  `;
  document.getElementById('loginBtn').onclick = async () => {
    const username = document.getElementById('u').value.trim();
    const password = document.getElementById('p').value;
    try {
      const res = await fetch(`${API_BASE}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) });
      if (!res.ok) throw new Error('Invalid credentials');
      const j = await res.json();
      setAuth({ accessToken: j.access_token, refreshToken: j.refresh_token, user: j.user, roles: j.roles });
      location.hash = '#/dashboard';
    } catch (e) {
      document.getElementById('err').textContent = 'Login failed';
    }
  };
}

async function viewDashboard() {
  app.innerHTML = `
    <div class="card-grid" id="cards"></div>
    <div class="row">
      <div class="panel col"><h2>Malicious Rate (%)</h2><canvas id="chartMal"></canvas></div>
      <div class="panel col"><h2>Total Volume</h2><canvas id="chartTotal"></canvas></div>
    </div>
    <div class="panel">
      <h2>Recent Email Activity</h2>
      <table class="table" id="recentTable">
        <thead><tr><th>Sender</th><th>Subject</th><th>Status</th><th>Time</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  `;
  const m = await (await apiFetch('/dashboard/metrics')).json();
  const cards = document.getElementById('cards');
  cards.innerHTML = `
    <div class="card"><h3>Total Emails</h3><div class="num">${m.total_emails ?? m.total}</div></div>
    <div class="card"><h3>Quarantined</h3><div class="num">${m.quarantined}</div></div>
    <div class="card"><h3>Blocked</h3><div class="num">${m.blocked}</div></div>
    <div class="card"><h3>Passed</h3><div class="num">${m.passed}</div></div>
  `;
  const now = new Date();
  const from = new Date(now.getTime() - 7*24*3600*1000).toISOString();
  const to = now.toISOString();
  const g = await (await apiFetch(`/dashboard/graph?series=both&date_from=${encodeURIComponent(from)}&date_to=${encodeURIComponent(to)}`)).json();
  const labels = g.labels || [];
  const total = g.total || [];
  const mal = g.malicious || [];
  const rate = labels.map((_, i) => {
    const t = Number(total[i] || 0);
    const m = Number(mal[i] || 0);
    return t > 0 ? Math.round((m / t) * 1000) / 10 : 0; // one decimal
  });
  if (window.Chart) {
    new Chart(document.getElementById('chartTotal'), { type:'line', data:{ labels, datasets:[{ label:'Total Volume', data: total, borderColor:'#4e9eff'}] }, options:{ responsive:true, scales:{ y:{ beginAtZero:true }}} });
    new Chart(document.getElementById('chartMal'), { type:'line', data:{ labels, datasets:[{ label:'Malicious %', data: rate, borderColor:'#ff5d5d'}] }, options:{ responsive:true, scales:{ y:{ beginAtZero:true, max: 100 }}} });
  } else {
    document.querySelectorAll('canvas').forEach(c => c.replaceWith(Object.assign(document.createElement('div'), {className:'muted', innerText:'Charts unavailable (CDN blocked)'})));
  }
  const recent = await (await apiFetch('/dashboard/recent')).json();
  const tbody = document.querySelector('#recentTable tbody');
  const parseSender = (s) => {
    if (!s) return { name: '', email: '' };
    const str = String(s);
    const m = str.match(/^\s*"?([^"<]*)"?\s*(?:<([^>]+)>)?\s*$/);
    if (m) {
      let name = (m[1] || '').trim();
      let email = (m[2] || '').trim();
      if (!name && email) name = email.split('@')[0];
      return { name, email };
    }
    return { name: str, email: '' };
  };
  const senderHtml = (s) => {
    const { name, email } = parseSender(s);
    const nameHtml = escapeHtml(name || email || '');
    const emailHtml = email ? ` <span class="sender-email">&lt;${escapeHtml(email)}&gt;</span>` : '';
    return nameHtml + emailHtml;
  };
  const fmtStatus = (s) => {
    const u = String(s || '').toUpperCase();
    if (u === 'BLOCK') return 'Blocked';
    if (u === 'QUARANTINE') return 'Quarantined';
    if (u === 'FORWARD') return 'Forwarded';
    return s || '';
  };
  tbody.innerHTML = recent.map(r => `<tr>
      <td>${senderHtml(r.sender)}</td>
      <td><a href="#/emails/${r.id}">${escapeHtml(r.subject||'')}</a></td>
      <td><span class="tag ${tagClass(r.status)}">${escapeHtml(fmtStatus(r.status))}</span></td>
      <td class="muted">${r.time||''}</td>
    </tr>`).join('');
}

async function viewPolicies() {
  app.innerHTML = `
    <div class="panel">
      <div class="toolbar">
        <h2>Policies</h2>
        <div class="spacer"></div>
        ${hasRole('admin') ? '<button id="newPol" class="btn">New Policy</button>' : ''}
      </div>
      <table class="table" id="polTable"><thead><tr><th>Name</th><th>Status</th><th>Last Modified</th></tr></thead><tbody></tbody></table>
    </div>
    <div id="polDetail"></div>
  `;
  const data = await (await apiFetch('/policies?limit=5')).json();
  const tbody = document.querySelector('#polTable tbody');
  tbody.innerHTML = (data.items||[]).map(p => `<tr data-id="${p.id}" class="polRow"><td>${escapeHtml(p.name)}</td><td>${p.status}</td><td class="muted">${p.last_modified}</td></tr>`).join('');
  tbody.querySelectorAll('tr.polRow').forEach(tr => tr.addEventListener('click', () => {
    const id = tr.getAttribute('data-id');
    location.hash = `#/policy/${id}`;
  }));
  const newBtn = document.getElementById('newPol');
  if (newBtn) newBtn.onclick = () => { location.hash = '#/policy/new'; };
}

async function viewPolicyDetail(id) {
  app.innerHTML = `
    <div class="toolbar">
      <a class="btn" href="#/policies">Back</a>
      <div class="spacer"></div>
      ${hasRole('admin') ? '<button id="savePol" class="btn">Save</button>' : ''}
      ${hasRole('admin') ? '<button id="activateBtn" class="btn btn-ok">Activate</button>' : ''}
    </div>
    <div class="panel" id="polWrap">
      <h2>Policy</h2>
      <div class="field"><label>Name</label><input id="polName" class="input" /></div>
      <div class="field"><label>Policy Version</label><input id="polVer" class="input" /></div>
      <div class="field"><label>Description</label><textarea id="polDesc" class="input" rows="3"></textarea></div>
    </div>
    <div class="panel">
      <div class="toolbar"><h2>Rules</h2><div class="spacer"></div>${hasRole('admin')?'<button id="addRule" class="btn">Add Rule</button>':''}</div>
      <table class="table rules-table" id="rulesTable">
        <thead><tr><th>Rule ID</th><th>Name</th><th>Category</th><th>Condition (JSON/YAML)</th><th>Action</th><th>Reasoning</th>${hasRole('admin')?'<th> </th>':''}</tr></thead>
        <tbody></tbody>
      </table>
    </div>
  `;
  const isNew = (id === 'new');
  let parsed;
  if (!isNew) {
    const d = await (await apiFetch(`/policy/${id}`)).json();
    parsed = d.parsed || { policy:{}, rules:[] };
  } else {
    parsed = { policy:{ name:'', version:'', description:'' }, rules:[] };
    // hide Activate for new policies until saved
    const ab = document.getElementById('activateBtn');
    if (ab) ab.style.display = 'none';
  }
  document.getElementById('polName').value = parsed.policy?.name || '';
  document.getElementById('polVer').value = parsed.policy?.version ?? '';
  document.getElementById('polDesc').value = parsed.policy?.description || '';
  const tbody = document.querySelector('#rulesTable tbody');
  function addRuleRow(rule) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${hasRole('admin')?`<input class="input r-id" value="${escapeHtml(rule?.id||'')}"/>`:`${escapeHtml(rule?.id||'')}`}</td>
      <td>${hasRole('admin')?`<input class="input r-name" value="${escapeHtml(rule?.name||'')}"/>`:`${escapeHtml(rule?.name||'')}`}</td>
      <td>${hasRole('admin')?`<input class="input r-cat" value="${escapeHtml(rule?.category||'')}"/>`:`${escapeHtml(rule?.category||'')}`}</td>
      <td>${hasRole('admin')?`<textarea class="input r-cond" rows="2">${escapeHtml((rule?.conditions?JSON.stringify(rule.conditions):'')||'')}</textarea>`:`<pre class="pre" style="margin:0">${escapeHtml(rule?.conditions?JSON.stringify(rule.conditions, null, 0):'')}</pre>`}</td>
      <td>${hasRole('admin')?`<input class="input r-act" value="${escapeHtml(rule?.action||'')}"/>`:`${escapeHtml(rule?.action||'')}`}</td>
      <td>${hasRole('admin')?`<input class="input r-reason" value="${escapeHtml(rule?.reasoning||'')}"/>`:`${escapeHtml(rule?.reasoning||'')}`}</td>
      ${hasRole('admin')?'<td><button class="btn btn-danger delRule">Delete</button></td>':''}
    `;
    if (hasRole('admin')) {
      tr.querySelector('.delRule').onclick = () => { tr.remove(); };
    }
    tbody.appendChild(tr);
  }
  (parsed.rules||[]).forEach(addRuleRow);
  const addBtn = document.getElementById('addRule');
  if (addBtn) addBtn.onclick = () => addRuleRow({ id:'', name:'', category:'', conditions:{}, action:'', reasoning:'' });

  const actBtn = document.getElementById('activateBtn');
  if (!isNew && actBtn) actBtn.onclick = async () => { await apiFetch(`/policy/${id}/activate`, { method:'PATCH' }); toast('Policy activated'); router(); };

  const saveBtn = document.getElementById('savePol');
  if (saveBtn) saveBtn.onclick = async () => {
    // Build object from form
    const policy = {
      name: document.getElementById('polName').value.trim(),
      version: document.getElementById('polVer').value.trim(),
      description: document.getElementById('polDesc').value.trim(),
    };
    const rules = Array.from(tbody.querySelectorAll('tr')).map(tr => {
      const get = sel => tr.querySelector(sel)?.value ?? '';
      let condRaw = tr.querySelector('.r-cond')?.value || '';
      let conditions = {};
      if (condRaw) {
        try { conditions = JSON.parse(condRaw); }
        catch { conditions = { expr: condRaw }; }
      }
      return {
        id: get('.r-id'),
        name: get('.r-name'),
        category: get('.r-cat'),
        conditions,
        action: get('.r-act'),
        reasoning: get('.r-reason'),
      };
    });
    // Serialize to YAML (JSON-compatible YAML)
    // Minimal YAML emitter using JSON as YAML (valid subset)
    const content = `policy:\n  name: ${JSON.stringify(policy.name)}\n  version: ${JSON.stringify(policy.version)}\n  description: ${JSON.stringify(policy.description)}\nrules:\n${rules.map(r => `  - id: ${JSON.stringify(r.id)}\n    name: ${JSON.stringify(r.name)}\n    category: ${JSON.stringify(r.category)}\n    conditions: ${JSON.stringify(r.conditions)}\n    action: ${JSON.stringify(r.action)}\n    reasoning: ${JSON.stringify(r.reasoning)}\n`).join('')}`;
    if (isNew) {
      const body = { name: policy.name || undefined, content };
      const res = await apiFetch('/policy', { method:'POST', body: JSON.stringify(body) });
      if (res.ok) {
        const created = await res.json();
        toast('Policy created');
        location.hash = `#/policy/${created.id}`;
      } else {
        toast('Create failed');
      }
    } else {
      const res = await apiFetch(`/policy/${id}`, { method:'PUT', body: JSON.stringify({ content }) });
      if (res.ok) { toast('Policy saved'); router(); } else { toast('Save failed'); }
    }
  };
}

async function viewEmails() {
  const folder = getQueryParam('folder') || 'quarantine';
  app.innerHTML = `
    <div class="panel">
      <div class="toolbar">
        <select id="folderSel">
          <option value="quarantine" ${folder==='quarantine'?'selected':''}>Quarantine</option>
          <option value="blocked" ${folder==='blocked'?'selected':''}>Blocked</option>
          <option value="all" ${folder==='all'?'selected':''}>All</option>
        </select>
        <div class="spacer"></div>
        ${hasRole('admin') ? '<button id="clearBtn" class="btn btn-danger">Clear Folder</button>' : ''}
      </div>
      <table class="table" id="mailTable"><thead><tr><th>Subject</th><th>From</th><th>Time</th><th>Status</th></tr></thead><tbody></tbody></table>
    </div>
  `;
  document.getElementById('folderSel').onchange = (e) => { const f = e.target.value; location.hash = `#/emails?folder=${f}`; };
  if (hasRole('admin')) {
    document.getElementById('clearBtn').onclick = async () => {
      const f = document.getElementById('folderSel').value;
      if (!confirm(`Clear ${f}?`)) return;
      try {
        if (f === 'all') {
          const r1 = await apiFetch(`/emails/clear`, { method: 'POST', body: JSON.stringify({ folder: 'quarantine' }) });
          const r2 = await apiFetch(`/emails/clear`, { method: 'POST', body: JSON.stringify({ folder: 'blocked' }) });
          if (!r1.ok || !r2.ok) {
            const t1 = r1.ok ? '' : await r1.text().catch(()=>'');
            const t2 = r2.ok ? '' : await r2.text().catch(()=>'');
            throw new Error(`(${r1.status}) ${t1} | (${r2.status}) ${t2}`.trim());
          }
        } else {
          const r = await apiFetch(`/emails/clear`, { method: 'POST', body: JSON.stringify({ folder: f }) });
          if (!r.ok) {
            const t = await r.text().catch(()=> '');
            throw new Error(`(${r.status}) ${t}`);
          }
        }
        toast('Cleared');
        router();
      } catch (e) {
        console.error('Clear failed:', e);
        toast(`Clear failed${e?.message?': ':''}${e?.message||''}`);
      }
    };
  }
  const page = await (await apiFetch(`/emails?folder=${encodeURIComponent(folder)}&page=1&page_size=50&sort=-created_at`)).json();
  const tbody = document.querySelector('#mailTable tbody');
  tbody.innerHTML = page.items.map(i => `<tr>
      <td><a href="#/emails/${i.id}">${escapeHtml(i.subject||'')}</a></td>
      <td>${escapeHtml(i.from||'')}</td>
      <td class="muted">${i.created_at||''}</td>
      <td>${i.final_decision||''}</td>
    </tr>`).join('');
}

async function viewEmailDetail(id) {
  app.innerHTML = `
    <div class="toolbar">
      <a class="btn" href="#/emails">Back</a>
      <div class="spacer"></div>
      ${hasRole('analyst','admin') ? `<button id="fwdBtn" class="btn">Forward</button>
      <button id="delBtn" class="btn btn-danger">Delete</button>` : ''}
    </div>
    <div id="wrap"></div>
  `;
  const d = await (await apiFetch(`/emails/${id}`)).json();
  document.getElementById('wrap').innerHTML = `
    <div class="panel"><h2>${escapeHtml(d.email?.subject || '')} <span class="tag ${tagClass(d.final_decision)}">${d.final_decision}</span></h2>
      <div class="muted">From: ${escapeHtml(d.email?.from || '')}</div>
      <div class="muted">Time: ${d.created_at || ''}</div>
      <h3>Reason</h3>
      <ul>${(d.reasons||[]).map(r=>`<li>${escapeHtml(r)}</li>`).join('')}</ul>
    </div>
    <div class="panel"><h3>Headers</h3><details><summary>Show (${Object.keys(d.headers||{}).length})</summary><pre class="pre" style="max-height:240px; overflow:auto;">${escapeHtml(JSON.stringify(d.headers || {}, null, 2))}</pre></details></div>
    <div class="panel"><h3>Email Body</h3>
      <h4>Rendered HTML</h4>
      <div class="mail-frame-wrap"><iframe id="mailFrame" class="mail-frame" sandbox></iframe></div>
      <details style="margin-top:12px;">
        <summary>Show Text Version</summary>
        <pre class="pre">${escapeHtml(d.body?.text || '')}</pre>
      </details>
    </div>
    <div class="panel"><h3>Attachments</h3>
      <div id="atts"></div>
    </div>
  `;
  // Render HTML safely inside sandboxed iframe
  try {
    const htmlSafe = (d.body && d.body.html_safe) || '';
    const frame = document.getElementById('mailFrame');
    if (frame) frame.srcdoc = String(htmlSafe || '').trim() || '<div style="font-family:system-ui;padding:8px;color:#666">(no HTML body)</div>';
  } catch {}
  const atts = await (await apiFetch(`/emails/${id}/attachments`)).json();
  const fmt = (n) => {
    const x = Number(n||0);
    if (!x) return '';
    const units = ['B','KB','MB','GB'];
    let u=0, v=x; while (v>=1024 && u<units.length-1){v/=1024;u++;}
    return `${v.toFixed(v<10&&u>0?1:0)} ${units[u]}`;
  };
  document.getElementById('atts').innerHTML = `<table class="table"><thead><tr><th>Filename</th><th>Size</th><th>Malicious</th></tr></thead><tbody>${
    (atts.items||[]).map(a => (
      '<tr><td>' + escapeHtml(a.filename||'') + '</td><td>' + fmt(a.size) + '</td><td>' + (a.is_malicious ? 'Yes' : 'No') + '</td></tr>'
    )).join('')
  }</tbody></table>`;
  const fwd = document.getElementById('fwdBtn');
  const del = document.getElementById('delBtn');
  if (fwd) fwd.onclick = async () => { await apiFetch('/forward', { method:'POST', body: JSON.stringify({ id }) }); toast('Forwarded'); };
  if (del) del.onclick = async () => { if (!confirm('Delete email?')) return; await apiFetch(`/emails/${id}`, { method:'DELETE' }); toast('Deleted'); location.hash = '#/emails'; };
}

async function viewSettings() {
  app.innerHTML = `
    <div class="panel"><h2>Settings</h2>
      <div class="field toggle-field"><label for="blockedToggle">Blocked Email Alerts</label>
        <input type="checkbox" id="blockedToggle" class="toggle" /></div>
      <div class="field toggle-field"><label for="quToggle">Quarantine Notifications</label>
        <input type="checkbox" id="quToggle" class="toggle" /></div>
      <button id="saveToggles" class="btn btn-ok">Save</button>
    </div>
    <div class="panel"><h2>Change Password</h2>
      <div class="field"><label>Current Password</label><input id="cp" type="password" class="input" /></div>
      <div class="field"><label>New Password</label><input id="np" type="password" class="input" /></div>
      <div class="field"><label>Confirm New Password</label><input id="cnp" type="password" class="input" /></div>
      <button id="chBtn" class="btn">Change Password</button>
    </div>
    <div class="panel"><h2>Spam Detection Level</h2>
      <div class="muted">Coming Soon</div>
    </div>
  `;
  const s = await (await apiFetch('/settings')).json();
  document.getElementById('blockedToggle').checked = !!s.alerts_blocked;
  document.getElementById('quToggle').checked = !!s.notifications_quarantine;
  document.getElementById('saveToggles').onclick = async () => {
    if (!hasRole('admin')) return alert('Requires admin');
    await apiFetch('/settings/alerts/blocked', { method:'PUT', body: JSON.stringify({ value: document.getElementById('blockedToggle').checked }) });
    await apiFetch('/settings/notifications/quarantine', { method:'PUT', body: JSON.stringify({ value: document.getElementById('quToggle').checked }) });
    toast('Saved');
  };
  document.getElementById('chBtn').onclick = async () => {
    const body = { current_password: document.getElementById('cp').value, new_password: document.getElementById('np').value, confirm_new_password: document.getElementById('cnp').value };
    const res = await apiFetch('/settings/change-password', { method:'POST', body: JSON.stringify(body) });
    if (res.ok) toast('Password changed'); else toast('Failed to change password');
  };
}

// Router
function router() {
  updateNavbar();
  const hash = location.hash || '#/';
  const segs = hash.replace('#/','').split('?')[0].split('/');
  const path = segs[0] || '';
  if (!state.accessToken && !['', 'login'].includes(path)) { viewLogin(); return; }
  switch (path) {
    case '': viewLanding(); break;
    case 'login': viewLogin(); break;
    case 'dashboard': viewDashboard(); break;
    case 'policy': {
      const id = pathParam('policy');
      if (id) viewPolicyDetail(id); else viewPolicies();
      break;
    }
    case 'policies': {
      const id = pathParam('policies');
      if (id) viewPolicyDetail(id); else viewPolicies();
      break;
    }
    case 'emails': {
      const id = pathParam('emails');
      if (id) viewEmailDetail(id); else viewEmails();
      break; }
    case 'settings': viewSettings(); break;
    default: viewDashboard();
  }
}

function pathParam(base) {
  // hash like #/emails/123
  const segs = location.hash.replace('#/','').split('?')[0].split('/');
  if (segs[0] === base && segs.length > 1) return segs[1];
  return null;
}

function getQueryParam(k) {
  const qs = location.hash.split('?')[1] || '';
  const params = new URLSearchParams(qs);
  return params.get(k);
}

function tagClass(status) {
  const s = (status||'').toUpperCase();
  if (s === 'BLOCK') return 'bad';
  if (s === 'QUARANTINE') return 'warn';
  return 'ok';
}

function escapeHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

window.addEventListener('hashchange', router);
document.addEventListener('DOMContentLoaded', router);
// In case DOMContentLoaded was already fired
if (document.readyState !== 'loading') {
  try { router(); } catch (e) { console.error(e); }
}

// --- Live notifications for new emails ---
async function _fetchLatestAnalysisMeta() {
  try {
    const res = await apiFetch('/analysis');
    if (!res.ok) return null;
    const items = await res.json();
    if (!Array.isArray(items) || items.length === 0) return null;
    // items are already sorted by created_at desc in storage
    const first = items[0] || null;
    if (!first) return null;
    return { created_at: first.created_at, subject: first.subject, from: first.from };
  } catch {
    return null;
  }
}

async function _checkForNewEmails() {
  const latest = await _fetchLatestAnalysisMeta();
  if (!latest || !latest.created_at) return;
  const prev = state.lastSeenCreatedAt;
  if (!prev) {
    state.lastSeenCreatedAt = latest.created_at;
    localStorage.setItem('lastSeenCreatedAt', state.lastSeenCreatedAt);
    return;
  }
  // Compare ISO strings lexicographically
  if (String(latest.created_at) > String(prev)) {
    state.lastSeenCreatedAt = latest.created_at;
    localStorage.setItem('lastSeenCreatedAt', state.lastSeenCreatedAt);
    const subj = latest.subject ? ` — ${latest.subject}` : '';
    toast(`New email received${subj}`);
    // If currently on emails view, refresh list
    const hash = location.hash || '#/';
    if (hash.startsWith('#/emails')) {
      try { await viewEmails(); } catch {}
    }
  }
}

function startLiveNotifications() {
  if (state.notifyTimer) return;
  // Prime the baseline without toasting
  _checkForNewEmails();
  state.notifyTimer = setInterval(_checkForNewEmails, 10000); // every 10s
}

function stopLiveNotifications() {
  if (state.notifyTimer) {
    clearInterval(state.notifyTimer);
    state.notifyTimer = null;
  }
}
