'use strict';

// ══════════════════════════════════════════════════════════
//  APP INIT — called after successful login
// ══════════════════════════════════════════════════════════
async function initApp() {
  await checkConnection();
  await Promise.all([fetchDashboardStats(), fetchAlerts()]);
  loadTrainingResult();

  setTimeout(() => { drawTrafficChart(); drawScatter(); }, 120);

  // Connect WebSocket for real-time updates
  wsConnect();

  // Load network interfaces for capture panel
  loadInterfaces();

  // Poll dashboard stats every 5s (fallback when WS is idle)
  clearInterval(state.statsPoller);
  state.statsPoller = setInterval(async () => {
    await fetchDashboardStats();
    const badge = document.querySelector('.nav-badge');
    const sev = state.stats?.severity_counts || {};
    if (badge && !state.captureRunning) badge.textContent = sev.critical || 0;
  }, 5000);

  // Tick chart every 2s when NOT in live capture mode
  setInterval(() => {
    if (!state.captureRunning) tickChart();
  }, 2000);

  setInterval(checkConnection, 10000);
}

// ══════════════════════════════════════════════════════════
//  CHECK BACKEND ON PAGE LOAD (before login)
// ══════════════════════════════════════════════════════════
checkConnection();
