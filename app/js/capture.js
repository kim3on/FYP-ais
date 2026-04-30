'use strict';

// ══════════════════════════════════════════════════════════
//  LIVE CAPTURE — WebSocket + live capture controls
// ══════════════════════════════════════════════════════════
const WS_URL = API.replace('http', 'ws') + '/ws/live';
let ws = null;
let wsReconnectTimer = null;

// Real-time chart data fed by WebSocket (60-point ring buffer)
const liveChart = { normal: new Array(60).fill(0), anomaly: new Array(60).fill(0) };

// Live flows buffer (max 50 rows shown in table)
const liveFlows    = [];
const MAX_LIVE_ROWS = 50;

// ── Live flows table ──────────────────────────────────────
function clearLiveFlows() {
  liveFlows.length = 0;
  const tbody = document.getElementById('live-flows-body');
  if (tbody) tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:20px;color:var(--text-tertiary);font-family:var(--font-mono);font-size:11px;">Cleared — waiting for new flows…</td></tr>';
}

function renderLiveFlowsTable() {
  const tbody = document.getElementById('live-flows-body');
  if (!tbody || !liveFlows.length) return;
  tbody.innerHTML = liveFlows.map(f => {
    const badge = f.anomaly
      ? `<span class="badge critical">Anomaly</span>`
      : `<span class="badge low">Normal</span>`;
    return `<tr>
      <td>${f.ts}</td>
      <td class="t-accent">${f.src_ip}</td>
      <td>${f.dst_ip}</td>
      <td>${f.dst_port}</td>
      <td>${f.proto}</td>
      <td>${f.packets}</td>
      <td>${f.bps}</td>
      <td>${badge}</td>
    </tr>`;
  }).join('');
  const wrap = tbody.closest('.tbl-wrap');
  if (wrap) wrap.scrollTop = 0;
}

// ── WebSocket ─────────────────────────────────────────────
function wsConnect() {
  if (ws && ws.readyState === WebSocket.OPEN) return;
  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    clearTimeout(wsReconnectTimer);
    updateCaptureUI(true);
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === 'ping')     { ws.send('ping'); return; }
      if (msg.type === 'snapshot') handleSnapshot(msg.data);
      if (msg.type === 'flow')     handleFlowUpdate(msg.data);
    } catch {}
  };

  ws.onclose = () => {
    updateCaptureUI(false);
    if (state.user) wsReconnectTimer = setTimeout(wsConnect, 4000);
  };

  ws.onerror = () => { ws.close(); };
}

function handleSnapshot(data) {
  if (data.chart_normal)  liveChart.normal  = data.chart_normal.map(v => Number(v) || 0);
  if (data.chart_anomaly) liveChart.anomaly = data.chart_anomaly.map(v => Number(v) || 0);
  setText('stat-packets',   (data.packet_count  || 0).toLocaleString());
  setText('stat-anomalies', (data.anomaly_count || 0).toLocaleString());
  if (data.recent_alerts && data.recent_alerts.length) {
    state.alerts = data.recent_alerts;
    renderRecentAlerts(state.alerts.slice(0, 5));
  }
  if (document.getElementById('panel-dashboard').classList.contains('active')) drawTrafficChart();
}

function handleFlowUpdate(data) {
  const isAnom = data.anomalies_found > 0;

  liveChart.normal.shift();
  liveChart.anomaly.shift();
  if (isAnom) {
    liveChart.normal.push(0);
    liveChart.anomaly.push(Number(data.anomalies_found) || 1);
  } else {
    liveChart.normal.push(Number(data.packet_count) || 1);
    liveChart.anomaly.push(0);
  }

  setText('stat-packets',    (data.packet_count  || 0).toLocaleString());
  setText('stat-anomalies',  (data.anomaly_count || 0).toLocaleString());
  setText('live-flow-count', (data.packet_count  || 0).toLocaleString());
  setText('live-anom-count', (data.anomaly_count || 0).toLocaleString());

  const ts = new Date().toISOString().substr(11, 8);
  const protoMap = { 6: 'TCP', 17: 'UDP', 1: 'ICMP' };
  liveFlows.unshift({
    ts,
    src_ip:   data.src_ip   || '—',
    dst_ip:   data.dst_ip   || '—',
    dst_port: data.dst_port || '—',
    proto:    protoMap[data.protocol] || data.protocol || '—',
    packets:  data.packet_count || '—',
    bps:      data.flow_bytes_s ? (data.flow_bytes_s / 1024).toFixed(1) + ' KB/s' : '—',
    anomaly:  isAnom,
  });
  if (liveFlows.length > MAX_LIVE_ROWS) liveFlows.pop();
  renderLiveFlowsTable();

  if (isAnom && data.alerts && data.alerts.length) {
    state.alerts = [...data.alerts, ...state.alerts].slice(0, 200);
    renderRecentAlerts(state.alerts.slice(0, 5));
    const badge = document.querySelector('.nav-badge');
    if (badge) {
      badge.textContent = parseInt(badge.textContent || '0') + data.anomalies_found;
      badge.style.animation = 'none';
      badge.style.background = 'var(--danger)';
      setTimeout(() => { badge.style.background = ''; }, 800);
    }
  }

  if (document.getElementById('panel-dashboard').classList.contains('active')) drawTrafficChart();
}

// ── Capture UI state ──────────────────────────────────────
function updateCaptureUI(wsConnected) {
  const dot   = document.getElementById('capture-status-dot');
  const label = document.getElementById('capture-status-label');
  const btn   = document.getElementById('btn-capture-toggle');
  if (!dot || !label || !btn) return;

  if (wsConnected && state.captureRunning) {
    dot.style.background = 'var(--danger)';
    label.textContent    = 'Capturing Live Traffic';
    label.style.color    = 'var(--danger)';
    btn.textContent      = '⬛ Stop Capture';
    btn.className        = 'btn btn-danger btn-sm';
  } else if (wsConnected) {
    dot.style.background = 'var(--success)';
    label.textContent    = 'Ready to Capture';
    label.style.color    = 'var(--success)';
    btn.textContent      = '▶ Start Live Capture';
    btn.className        = 'btn btn-accent btn-sm';
  } else {
    dot.style.background = 'var(--text-tertiary)';
    label.textContent    = 'WebSocket Offline';
    label.style.color    = 'var(--text-tertiary)';
    btn.textContent      = '▶ Start Live Capture';
    btn.className        = 'btn btn-default btn-sm';
  }
}

// ── Capture controls ──────────────────────────────────────
async function toggleCapture() {
  if (!state.backendOnline) { toast('Backend is offline', 'error'); return; }
  if (!state.captureRunning) await startCapture();
  else await stopCapture();
}

async function startCapture() {
  let iface = null;
  const sel = document.getElementById('iface-select');
  if (sel && sel.value && sel.value !== 'default') iface = sel.value;
  try {
    const url = '/api/capture/start' + (iface ? `?interface=${iface}` : '');
    await api.post(url, {});
    state.captureRunning = true;
    updateCaptureUI(true);
    toast('Live capture started', 'success');
    wsConnect();
  } catch (err) {
    toast(err.message || 'Could not start capture — need root/admin privileges', 'error');
  }
}

async function stopCapture() {
  try {
    await api.post('/api/capture/stop', {});
    state.captureRunning = false;
    updateCaptureUI(ws && ws.readyState === WebSocket.OPEN);
    toast('Capture stopped', 'info');
  } catch (err) {
    toast(err.message || 'Stop failed', 'error');
  }
}

async function loadInterfaces() {
  const sel = document.getElementById('iface-select');
  if (!sel) return;
  try {
    const data = await api.get('/api/capture/interfaces');
    sel.innerHTML = `<option value="default">Auto-detect</option>` +
      (data.interfaces || []).map(i => `<option value="${i}">${i}</option>`).join('');
  } catch {
    sel.innerHTML = `<option value="default">Auto-detect</option>`;
  }
}
