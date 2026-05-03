/**
 * api/index.js — All FastAPI calls, matched to exact backend routes.
 *
 * Routes (from backend routers):
 *   POST /api/auth/login
 *   POST /api/train          GET /api/train/logs    GET /api/train/result
 *   POST /api/detect         GET /api/detect/logs   GET /api/detect/result
 *   GET  /api/alerts         PATCH /api/alerts/:id/fp
 *   POST /api/capture/start  POST /api/capture/stop
 *   GET  /api/capture/status GET /api/capture/interfaces  GET /api/capture/chartdata
 *   GET  /api/system/status  GET /api/dashboard/stats     GET /api/model/summary
 *   PATCH /api/settings
 *   WS   /ws/live
 */

// ── Auth ──────────────────────────────────────────────────────
export async function login(username, password) {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error('Invalid credentials');
  return res.json();
}

// ── Dashboard / System ────────────────────────────────────────
export async function getSystemStatus()  { return apiFetch('/api/system/status'); }
export async function getDashboardStats(){ return apiFetch('/api/dashboard/stats'); }
export async function getModelSummary()  { return apiFetch('/api/model/summary'); }

// ── Alerts ────────────────────────────────────────────────────
export async function getAlerts(limit = 200) {
  return apiFetch(`/api/alerts?limit=${limit}`);
}
export async function markFalsePositive(alertId) {
  return apiFetch(`/api/alerts/${alertId}/fp`, { method: 'PATCH' });
}
export async function clearAlerts() {
  return apiFetch('/api/alerts', { method: 'DELETE' });
}

// ── Training ──────────────────────────────────────────────────
export async function startTraining(file, params = {}) {
  const form = new FormData();
  form.append('file', file);
  
  const query = new URLSearchParams(params).toString();
  const url = query ? `/api/train?${query}` : '/api/train';

  const res = await fetch(url, {
    method: 'POST',
    headers: authHeader(),
    body: form,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
export async function getTrainingLogs()   { return apiFetch('/api/train/logs'); }
export async function getTrainingResult() { return apiFetch('/api/train/result'); }

// ── Detection ─────────────────────────────────────────────────
export async function detectFromFile(file, limit) {
  const form = new FormData();
  form.append('file', file);
  if (limit) form.append('limit', String(limit));
  const res = await fetch('/api/detect', {
    method: 'POST',
    headers: authHeader(),
    body: form,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
export async function getDetectionLogs()   { return apiFetch('/api/detect/logs'); }
export async function getDetectionResult() { return apiFetch('/api/detect/result'); }

// ── Capture ───────────────────────────────────────────────────
export async function getInterfaces()    { return apiFetch('/api/capture/interfaces'); }
export async function getCaptureStatus() { return apiFetch('/api/capture/status'); }
export async function getChartData()     { return apiFetch('/api/capture/chartdata'); }

export async function startCapture(iface) {
  return apiFetch('/api/capture/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ interface: iface }),
  });
}
export async function stopCapture() {
  return apiFetch('/api/capture/stop', { method: 'POST' });
}
export async function clearRawFlows() {
  return apiFetch('/api/capture/flows', { method: 'DELETE' });
}

// ── Firewall / IP Blocking ────────────────────────────────────
export async function blockIP(ip, reason) {
  return apiFetch('/api/firewall/block', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, reason }),
  });
}
export async function unblockIP(ip) {
  return apiFetch('/api/firewall/unblock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  });
}
export async function getBlockedIPs() {
  return apiFetch('/api/firewall/blocked');
}

// ── Settings ──────────────────────────────────────────────────
export async function updateSettings(settings) {
  return apiFetch('/api/settings', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  });
}

// ── Helpers ───────────────────────────────────────────────────
function authHeader() {
  const token = localStorage.getItem('ais_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function apiFetch(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: { ...authHeader(), ...(options.headers || {}) },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }
  return res.json();
}
