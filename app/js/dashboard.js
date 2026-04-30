'use strict';

// ══════════════════════════════════════════════════════════
//  DASHBOARD STATS
// ══════════════════════════════════════════════════════════
async function fetchDashboardStats() {
  try {
    const data = await api.get('/api/dashboard/stats');
    state.stats = data;

    setText('stat-packets',   (data.total_packets   || 0).toLocaleString());
    setText('stat-anomalies', (data.anomalies_total  || 0).toLocaleString());

    const sev = data.severity_counts || {};
    setText('stat-critical',   sev.critical || 0);
    setText('stat-antibodies', data.active_antibodies || 0);

    const st = document.getElementById('system-status');
    if (st) {
      const s = data.system_status || 'idle';
      st.className = `status-badge ${s === 'active' ? 'active' : s === 'learning' ? 'learning' : 'active'}`;
      const label = s === 'active' ? 'System Active' : s === 'learning' ? 'Learning' : 'Idle';
      st.innerHTML = `<div class="status-dot"></div>${label}`;
    }

    const badge = document.querySelector('.nav-badge');
    if (badge) badge.textContent = sev.critical || 0;

  } catch { /* backend offline — keep existing display */ }
}

// ══════════════════════════════════════════════════════════
//  ALERTS
// ══════════════════════════════════════════════════════════
async function fetchAlerts(severity = null) {
  try {
    const qs   = severity ? `?severity=${severity}&limit=100` : '?limit=100';
    const data = await api.get('/api/alerts' + qs);
    state.alerts = data.alerts || [];
    renderAlertTable(state.alerts);
    updateAlertSeverityCounts(state.alerts);
    renderRecentAlerts(state.alerts.slice(0, 5));
    renderScatterList(state.alerts.slice(0, 6));
  } catch {
    if (state.alerts.length === 0) showEmptyAlerts();
  }
}

function updateAlertSeverityCounts(alerts) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  alerts.forEach(a => { if (counts[a.severity] !== undefined) counts[a.severity]++; });
  setText('alert-count-critical', counts.critical);
  setText('alert-count-high',     counts.high);
  setText('alert-count-medium',   counts.medium);
  setText('alert-count-low',      counts.low);
}

function showEmptyAlerts() {
  const tbody = document.getElementById('alert-table-body');
  if (tbody) tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--text-tertiary);font-family:var(--font-mono);font-size:11px;">No alerts yet — upload a log file to run detection</td></tr>`;
}

function renderAlertTable(alerts) {
  const tbody = document.getElementById('alert-table-body');
  if (!tbody) return;
  if (!alerts.length) { showEmptyAlerts(); return; }
  tbody.innerHTML = alerts.map(a => {
    const zd = a.is_zero_day || a.attack_type === 'Zero-Day Candidate';
    const attackCell = zd
      ? `<span class="badge zero-day" title="Novel pattern — no known attack signature matched">⚠ Zero-Day Candidate</span>`
      : (a.attack_type || a.type || '');
    return `<tr${zd ? ' style="background:rgba(139,92,246,0.04);"' : ''}>
      <td>${a.timestamp || a.ts || ''}</td>
      <td class="t-primary">${attackCell}</td>
      <td class="t-accent">${a.src_ip || a.src || ''}</td>
      <td>${a.dst_ip || a.dst || ''}</td>
      <td>${a.dst_port || a.port || ''}</td>
      <td>${(a.protocol || a.proto || '').toUpperCase()}</td>
      <td><span class="badge ${a.severity || a.sev}">${cap(a.severity || a.sev)}</span></td>
      <td class="fw-600">${a.confidence_pct || a.conf || ''}</td>
    </tr>`;
  }).join('');
}

function renderRecentAlerts(alerts) {
  const tbody = document.getElementById('recent-alerts-body');
  if (!tbody) return;
  if (!alerts || !alerts.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--text-tertiary);font-family:var(--font-mono);font-size:11px;">No detections yet</td></tr>`;
    return;
  }
  tbody.innerHTML = alerts.map(a => {
    const zd = a.is_zero_day || a.attack_type === 'Zero-Day Candidate';
    const attackCell = zd
      ? `<span class="badge zero-day">⚠ Zero-Day</span>`
      : (a.attack_type || a.type || '');
    return `<tr${zd ? ' style="background:rgba(139,92,246,0.04);"' : ''}>
      <td>${a.timestamp || a.ts || ''}</td>
      <td class="t-primary">${attackCell}</td>
      <td class="t-accent">${a.src_ip || a.src || ''}</td>
      <td>${a.dst_ip || a.dst || ''}</td>
      <td>${(a.protocol || a.proto || '').toUpperCase()}</td>
      <td><span class="badge ${a.severity || a.sev}">${cap(a.severity || a.sev)}</span></td>
      <td class="fw-600">${a.confidence_pct || a.conf || ''}</td>
    </tr>`;
  }).join('');
}

function renderScatterList(alerts) {
  const tbody = document.getElementById('scatter-list-body');
  if (!tbody || !alerts || !alerts.length) return;
  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td class="t-accent">${a.src_ip || a.src || ''}</td>
      <td>${a.dst_port || a.port || ''}</td>
      <td>${(a.protocol || a.proto || '').toUpperCase()}</td>
      <td><span class="badge ${a.severity || a.sev}">${cap(a.severity || a.sev)}</span></td>
    </tr>`).join('');
}

async function filterAlerts(type, btn) {
  document.querySelectorAll('#panel-alerts .seg-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  await fetchAlerts(type === 'all' ? null : type);
}

function exportAlerts() {
  const rows = [['Timestamp', 'Attack Type', 'Source IP', 'Dest IP', 'Port', 'Protocol', 'Severity', 'Confidence']];
  state.alerts.forEach(a => rows.push([
    a.timestamp || a.ts, a.attack_type || a.type,
    a.src_ip || a.src, a.dst_ip || a.dst,
    a.dst_port || a.port, a.protocol || a.proto,
    a.severity || a.sev, a.confidence_pct || a.conf,
  ]));
  const blob = new Blob([rows.map(r => r.join(',')).join('\n')], { type: 'text/csv' });
  Object.assign(document.createElement('a'), {
    href: URL.createObjectURL(blob), download: 'ais_alerts.csv',
  }).click();
  toast('Exported ' + state.alerts.length + ' alerts', 'success');
}
