'use strict';

// ══════════════════════════════════════════════════════════
//  NAVIGATION
// ══════════════════════════════════════════════════════════
const TITLES = {
  dashboard: 'Dashboard',
  training:  'AIS Training',
  alerts:    'Alert Log',
  settings:  'Settings',
  profile:   'Profile',
};

function showPanel(name, navEl) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('active');
  document.getElementById('topbar-title').textContent = TITLES[name] || name;
  if (navEl) navEl.classList.add('active');

  if (name === 'dashboard') {
    setTimeout(() => { drawTrafficChart(); drawScatter(); }, 60);
    fetchDashboardStats();
  }
  if (name === 'alerts')   fetchAlerts();
  if (name === 'settings') fetchModelSummary();
  if (name === 'profile')  renderProfile();
  if (name === 'training') loadTrainingResult();
}

// ══════════════════════════════════════════════════════════
//  RESIZE — redraw charts when window changes size
// ══════════════════════════════════════════════════════════
window.addEventListener('resize', () => {
  if (document.getElementById('panel-dashboard').classList.contains('active')) {
    drawTrafficChart();
    drawScatter();
  }
});
