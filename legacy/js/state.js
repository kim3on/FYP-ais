'use strict';

// ══════════════════════════════════════════════════════════
//  APP STATE
// ══════════════════════════════════════════════════════════
const state = {
  user:           null,       // { username, role }
  alerts:         [],         // full alert list from backend
  stats:          {},         // dashboard stats
  backendOnline:  false,
  trainingFile:   null,       // selected File object
  trainingActive: false,
  logPoller:      null,       // setInterval id for log polling
  statsPoller:    null,       // setInterval id for dashboard refresh
  activeModel:    'nsa',
  captureRunning: false,
};

// ── Shared DOM helper ─────────────────────────────────────
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function cap(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}
