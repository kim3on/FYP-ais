'use strict';

// ══════════════════════════════════════════════════════════
//  THEME
// ══════════════════════════════════════════════════════════
let isDark = true;

function toggleTheme() {
  isDark = !isDark;
  document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
  const icon = isDark ? '🌙' : '☀️';
  ['app-theme-btn', 'login-theme-btn'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = icon;
  });
  if (document.getElementById('panel-dashboard').classList.contains('active')) {
    setTimeout(() => { drawTrafficChart(); drawScatter(); }, 40);
  }
}

// ══════════════════════════════════════════════════════════
//  TOAST NOTIFICATIONS
// ══════════════════════════════════════════════════════════
function toast(msg, type = 'info') {
  document.querySelectorAll('.toast').forEach(t => t.remove());
  const colors = {
    info: 'var(--accent)', success: 'var(--success)',
    error: 'var(--danger)', warning: 'var(--warning)',
  };
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  Object.assign(t.style, {
    position: 'fixed', bottom: '20px', right: '20px', zIndex: '9999',
    background: 'var(--bg-elevated)', border: `1px solid ${colors[type]}`,
    color: colors[type], borderRadius: 'var(--radius)', padding: '10px 16px',
    fontSize: '12px', fontWeight: '500', fontFamily: 'var(--font-sans)',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
    animation: 'fadeUp 0.2s ease both',
  });
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

// ══════════════════════════════════════════════════════════
//  CONNECTION INDICATOR
// ══════════════════════════════════════════════════════════
function setConnectionStatus(online) {
  state.backendOnline = online;
  const dot   = document.getElementById('conn-dot');
  const label = document.getElementById('conn-label');
  if (!dot || !label) return;
  if (online) {
    dot.style.background = 'var(--success)';
    label.textContent    = 'API Connected';
    label.style.color    = 'var(--success)';
  } else {
    dot.style.background = 'var(--danger)';
    label.textContent    = 'API Offline';
    label.style.color    = 'var(--danger)';
  }
}

async function checkConnection() {
  try {
    await api.get('/health');
    setConnectionStatus(true);
  } catch {
    setConnectionStatus(false);
  }
}

// ══════════════════════════════════════════════════════════
//  CLOCK
// ══════════════════════════════════════════════════════════
setInterval(() => {
  const el = document.getElementById('topbar-clock');
  if (el) el.textContent = new Date().toISOString().substr(11, 8) + ' UTC';
}, 1000);
