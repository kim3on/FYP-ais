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
  let res;
  try {
    res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
  } catch {
    throw new Error('Backend is not reachable');
  }
  if (!res.ok) {
    if (res.status === 401) throw new Error('Invalid credentials');
    const text = await res.text();
    throw new Error(text || `Login failed (HTTP ${res.status})`);
  }
  return res.json();
}

export async function getCurrentUser() {
  return apiFetch('/api/auth/me');
}

export async function updateCurrentUserProfile(profile) {
  return apiFetch('/api/auth/me/profile', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(profile),
  });
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
export async function exportAlertsCSV(params = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, String(value));
    }
  });
  const url = `/api/alerts/export.csv${query.toString() ? `?${query}` : ''}`;
  const res = await fetch(url, { headers: authHeader() });
  if (!res.ok) throw new Error(await res.text());
  const blob = await res.blob();
  const disposition = res.headers.get('Content-Disposition') || '';
  const match = disposition.match(/filename="?([^"]+)"?/i);
  return {
    blob,
    filename: match?.[1] || `alerts_summary_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`,
  };
}
export async function exportRawAlertsCSV(params = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, String(value));
    }
  });
  const url = `/api/alerts/export_raw.csv${query.toString() ? `?${query}` : ''}`;
  const res = await fetch(url, { headers: authHeader() });
  if (!res.ok) throw new Error(await res.text());
  const blob = await res.blob();
  const disposition = res.headers.get('Content-Disposition') || '';
  const match = disposition.match(/filename="?([^"]+)"?/i);
  return {
    blob,
    filename: match?.[1] || `alerts_raw_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`,
  };
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
export async function getTrainingRuns(params = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, String(value));
    }
  });
  return apiFetch(`/api/train/runs${query.toString() ? `?${query}` : ''}`);
}
export async function exportTrainingRunsCSV(params = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, String(value));
    }
  });
  const url = `/api/train/runs/export.csv${query.toString() ? `?${query}` : ''}`;
  const res = await fetch(url, { headers: authHeader() });
  if (!res.ok) throw new Error(await res.text());
  const blob = await res.blob();
  const disposition = res.headers.get('Content-Disposition') || '';
  const match = disposition.match(/filename="?([^"]+)"?/i);
  return {
    blob,
    filename: match?.[1] || `training_runs_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`,
  };
}

// ── Detection ─────────────────────────────────────────────────
export async function detectFromFile(file, limit, offset = 0, params = {}) {
  const form = new FormData();
  form.append('file', file);
  const queryParams = new URLSearchParams(params);
  if (limit) queryParams.set('limit', String(limit));
  if (offset) queryParams.set('offset', String(offset));
  const query = queryParams.toString() ? `?${queryParams}` : '';
  const res = await fetch(`/api/detect${query}`, {
    method: 'POST',
    headers: authHeader(),
    body: form,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
export async function getDetectionLogs()   { return apiFetch('/api/detect/logs'); }
export async function getDetectionResult(options = {}) {
  const alertsLimit = options.alertsLimit ?? 500;
  const query = alertsLimit == null ? '' : `?alerts_limit=${encodeURIComponent(alertsLimit)}`;
  return apiFetch(`/api/detect/result${query}`);
}

// ── Capture ───────────────────────────────────────────────────
export async function getInterfaces()    { return apiFetch('/api/capture/interfaces'); }
export async function getCaptureStatus() { return apiFetch('/api/capture/status'); }
export async function getChartData()     { return apiFetch('/api/capture/chartdata'); }

export async function startCapture(iface) {
  const query = iface ? `?interface=${encodeURIComponent(iface)}` : '';
  return apiFetch(`/api/capture/start${query}`, { method: 'POST' });
}
export async function stopCapture() {
  return apiFetch('/api/capture/stop', { method: 'POST' });
}
export async function clearRawFlows() {
  return apiFetch('/api/capture/flows', { method: 'DELETE' });
}
export async function submitFlowFile(file, limit = 1000) {
  const form = new FormData();
  form.append('file', file);
  const query = limit ? `?limit=${encodeURIComponent(String(limit))}` : '';
  const res = await fetch(`/api/capture/submit-flow${query}`, {
    method: 'POST',
    headers: authHeader(),
    body: form,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

// ── Firewall / IP Blocklist ───────────────────────────────────
export async function blockIP(ip, reason, devMode = false) {
  return apiFetch(`/api/firewall/block${devMode ? '?dev=1' : ''}`, {
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

// ── Users ─────────────────────────────────────────────────────
export async function getUsers() {
  return apiFetch('/api/users');
}

export async function createUser(username, password, role) {
  return apiFetch('/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, role }),
  });
}

export async function deleteUser(username) {
  return apiFetch(`/api/users/${username}`, {
    method: 'DELETE',
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
