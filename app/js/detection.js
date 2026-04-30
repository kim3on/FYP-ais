'use strict';

// ══════════════════════════════════════════════════════════
//  BATCH DETECTION — upload log + stream results
// ══════════════════════════════════════════════════════════

function triggerDetectPick() {
  document.getElementById('detect-file-input').click();
}

let _lastDetectResult = null;
let _detectPoller     = null;

async function onDetectFileSelected(input) {
  const file = input.files[0];
  if (!file) return;
  if (!state.backendOnline) { toast('Backend is offline', 'error'); return; }

  const uploadZone  = document.getElementById('detect-upload-zone');
  const runningEl   = document.getElementById('detect-running');
  const progressEl  = document.getElementById('detect-progress');
  const pctEl       = document.getElementById('detect-progress-pct');
  const logEl       = document.getElementById('detect-log');
  const resultsCard = document.getElementById('detect-results-card');

  uploadZone.style.display  = 'none';
  runningEl.style.display   = 'block';
  resultsCard.style.display = 'none';
  logEl.innerHTML = '';
  if (progressEl) progressEl.style.width = '0%';
  if (pctEl) pctEl.textContent = '0%';

  const appendLog = (line) => {
    const div = document.createElement('div');
    const ts  = new Date().toISOString().substr(11, 8);
    let cls = 'log-info';
    if (line.includes('[OK]') || line.includes('[COMPLETE]')) cls = 'log-ok';
    else if (line.includes('[WARN]'))  cls = 'log-warn';
    else if (line.includes('[ERROR]')) cls = 'log-err';
    div.innerHTML = `<span class="log-ts">[${ts}]</span><span class="${cls}">${line.replace(/^\[.*?\]\s*/, '')}</span>`;
    logEl.appendChild(div);
    logEl.scrollTop = logEl.scrollHeight;
  };

  toast('Detection started — streaming logs…', 'info');

  const form = new FormData();
  form.append('file', file);

  try {
    await api.postForm('/api/detect', form);
  } catch (err) {
    runningEl.style.display  = 'none';
    uploadZone.style.display = 'block';
    toast(err.message || 'Failed to start detection', 'error');
    input.value = '';
    return;
  }

  appendLog('[DETECT] Detection task queued on backend.');
  if (progressEl) progressEl.style.width = '10%';

  let lastCount = 0;
  let fakePct   = 10;
  clearInterval(_detectPoller);

  _detectPoller = setInterval(async () => {
    try {
      const { logs, status } = await api.get('/api/detect/logs');
      logs.slice(lastCount).forEach(line => appendLog(line));
      lastCount = logs.length;

      if (status === 'running' && fakePct < 90) {
        fakePct = Math.min(fakePct + 8, 90);
        if (progressEl) progressEl.style.width = fakePct + '%';
        if (pctEl) pctEl.textContent = fakePct + '%';
      }

      if (status === 'done' || status === 'error') {
        clearInterval(_detectPoller); _detectPoller = null;
        if (progressEl) progressEl.style.width = '100%';
        if (pctEl) pctEl.textContent = '100%';

        if (status === 'error') { toast('Detection encountered an error — check the log', 'error'); return; }

        const result = await api.get('/api/detect/result');
        _lastDetectResult = result;

        await new Promise(r => setTimeout(r, 400));
        runningEl.style.display  = 'none';
        uploadZone.style.display = 'block';
        uploadZone.style.borderColor = 'var(--success)';
        uploadZone.style.background  = 'var(--success-subtle)';
        uploadZone.innerHTML = `
          <div class="upload-ico" style="width:28px;height:28px;margin-bottom:7px;background:var(--success-subtle);color:var(--success);">
            <svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4.5 9l3.5 3.5L14 5"/><circle cx="9" cy="9" r="7.5"/></svg>
          </div>
          <div class="upload-main" style="font-size:12px;color:var(--success);">${file.name}</div>
          <div class="upload-sub">Detection complete &middot; click to re-run with new file</div>`;
        uploadZone.onclick = () => document.getElementById('detect-file-input').click();

        renderDetectResults(result, file.name);
        fetchDashboardStats();
        toast(`Detection complete — ${result.anomalies_found.toLocaleString()} anomalies in ${result.total_checked.toLocaleString()} flows`, 'success');
      }
    } catch { /* ignore transient poll errors */ }
  }, 1000);

  input.value = '';
}

function renderDetectResults(result, filename) {
  const card = document.getElementById('detect-results-card');
  card.style.display = 'block';
  card.scrollIntoView({ behavior: 'smooth', block: 'start' });

  setText('detect-results-filename',
    `${filename} · model: ${(result.model_used || 'nsa').toUpperCase()} · analysed ${new Date().toLocaleTimeString()}`);

  // IP notice when N/A
  const hasNoIP = (result.alerts || []).some(a => a.src_ip === 'N/A');
  let noteEl = document.getElementById('detect-ip-note');
  if (!noteEl) {
    noteEl = document.createElement('div'); noteEl.id = 'detect-ip-note';
    noteEl.style.cssText = 'font-size:11px;color:var(--warning);background:var(--warning-subtle,rgba(251,191,36,.08));border:1px solid var(--warning-border,rgba(251,191,36,.2));border-radius:var(--radius);padding:7px 12px;margin-bottom:12px;font-family:var(--font-mono);';
    noteEl.innerHTML = '&#9432; <strong>Src IP / Dst IP / Port</strong> show <em>N/A</em> because CIC-IDS-2017 flow stat files do not include endpoint metadata — only traffic statistics are present.';
    const bd = document.querySelector('#detect-results-card .card-bd');
    if (bd) bd.insertBefore(noteEl, bd.firstChild);
  }
  noteEl.style.display = hasNoIP ? 'block' : 'none';

  // Summary numbers
  setText('dr-total',     (result.total_checked  || 0).toLocaleString());
  setText('dr-anomalies', (result.anomalies_found || 0).toLocaleString());
  setText('dr-normal',    (result.normal_count    || 0).toLocaleString());
  setText('dr-rate',      (result.detection_rate_pct || 0).toFixed(1) + '%');

  // Zero-day candidate count
  const zdEl = document.getElementById('dr-zero-day');
  if (zdEl) {
    const zdCount = result.zero_day_candidates || 0;
    zdEl.textContent = zdCount.toLocaleString();
    const zdCard = document.getElementById('dr-zero-day-card');
    if (zdCard) zdCard.style.display = zdCount > 0 ? 'block' : 'none';
  }

  // Severity breakdown
  const sev = result.severity_counts || {};
  const sevDefs = [
    { key: 'critical', label: 'Critical', cls: 'danger'  },
    { key: 'high',     label: 'High',     cls: 'warning' },
    { key: 'medium',   label: 'Medium',   cls: 'accent'  },
    { key: 'low',      label: 'Low',      cls: 'success' },
  ];
  const sevTotal = Object.values(sev).reduce((a, b) => a + b, 0) || 1;
  document.getElementById('dr-severity').innerHTML = sevDefs.map(d => {
    const n = sev[d.key] || 0;
    const pct = Math.round(n / sevTotal * 100);
    return `<div>
      <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px;">
        <span class="fw-500">${d.label}</span>
        <span class="mono c-${d.cls}">${n.toLocaleString()}</span>
      </div>
      <div style="background:var(--border);border-radius:3px;height:4px;overflow:hidden;">
        <div style="width:${pct}%;height:100%;background:var(--${d.cls});border-radius:3px;transition:width .4s;"></div>
      </div></div>`;
  }).join('');

  // Attack categories
  const catMap = {};
  (result.alerts || []).forEach(a => { const t = a.attack_type || 'Unknown'; catMap[t] = (catMap[t] || 0) + 1; });
  const catEl = document.getElementById('dr-categories');
  const catEntries = Object.entries(catMap).sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (!catEntries.length) {
    catEl.innerHTML = '<span style="font-size:11px;color:var(--text-tertiary);">No attack categories (all flows classified as normal)</span>';
  } else {
    const catTotal = catEntries.reduce((s, [, n]) => s + n, 0) || 1;
    catEl.innerHTML = catEntries.map(([cat, n]) => {
      const pct = Math.round(n / catTotal * 100);
      return `<div style="display:flex;align-items:center;gap:8px;font-size:11px;">
        <div style="flex:1;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;" title="${cat}">${cat}</div>
        <div style="width:60px;background:var(--border);border-radius:2px;height:3px;overflow:hidden;flex-shrink:0;">
          <div style="width:${pct}%;height:100%;background:var(--danger);border-radius:2px;"></div></div>
        <span class="mono fw-600 c-danger" style="min-width:28px;text-align:right;">${n}</span>
      </div>`;
    }).join('');
  }

  // Sample table
  const tbody  = document.getElementById('detect-results-body');
  const sample = (result.alerts || []).slice(0, 20);
  if (!sample.length) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:16px;color:var(--text-tertiary);font-family:var(--font-mono);font-size:11px;">No anomalies detected — all flows classified as normal</td></tr>`;
  } else {
    tbody.innerHTML = sample.map(a => {
      const zd = a.is_zero_day || a.attack_type === 'Zero-Day Candidate';
      const attackCell = zd
        ? `<span class="badge zero-day" title="Novel pattern — no known attack signature matched">⚠ Zero-Day Candidate</span>`
        : (a.attack_type || '');
      return `<tr${zd ? ' style="background:rgba(139,92,246,0.04);"' : ''}>
        <td>${a.timestamp || ''}</td>
        <td class="t-accent">${a.src_ip || 'N/A'}</td>
        <td>${a.dst_ip || 'N/A'}</td>
        <td>${a.dst_port || 'N/A'}</td>
        <td>${(a.protocol || 'N/A').toUpperCase()}</td>
        <td class="t-primary">${attackCell}</td>
        <td><span class="badge ${a.severity}">${cap(a.severity)}</span></td>
        <td class="fw-600">${a.confidence_pct || ''}</td>
      </tr>`;
    }).join('');
  }
}

function exportDetectResults() {
  if (!_lastDetectResult) return;
  const rows = [['Time', 'Src IP', 'Dst IP', 'Port', 'Proto', 'Attack Type', 'Severity', 'Confidence']];
  (_lastDetectResult.alerts || []).forEach(a => rows.push([
    a.timestamp, a.src_ip, a.dst_ip, a.dst_port,
    a.protocol, a.attack_type, a.severity, a.confidence_pct,
  ]));
  const blob = new Blob([rows.map(r => r.join(',')).join('\n')], { type: 'text/csv' });
  Object.assign(document.createElement('a'), {
    href: URL.createObjectURL(blob), download: 'detection_results.csv',
  }).click();
  toast('Exported ' + (_lastDetectResult.alerts || []).length + ' alerts', 'success');
}
