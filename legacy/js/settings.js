'use strict';

// ══════════════════════════════════════════════════════════
//  SETTINGS — model switch
// ══════════════════════════════════════════════════════════
async function fetchModelSummary() {
  try {
    const data = await api.get('/api/model/summary');
    state.activeModel = data.active || 'nsa';

    setText('settings-api-status', '● Connected');
    const el = document.getElementById('settings-api-status');
    if (el) el.className = 'ir-val success';

    const nsa = data.nsa || {};
    if (nsa.mature_detectors) setText('settings-antibodies', nsa.mature_detectors);
  } catch {
    const el = document.getElementById('settings-api-status');
    if (el) { el.textContent = '● Offline'; el.className = 'ir-val'; el.style.color = 'var(--danger)'; }
  }
}

async function switchModel(model, btn) {
  document.querySelectorAll('#panel-settings .seg-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  try {
    await api.patch('/api/settings', { active_model: model });
    state.activeModel = model;
    toast('Switched to ' + (model === 'nsa' ? 'AIS (NSA)' : 'Isolation Forest'), 'success');
  } catch {
    toast('Could not update model setting', 'error');
  }
}

// ══════════════════════════════════════════════════════════
//  PROFILE
// ══════════════════════════════════════════════════════════
function renderProfile() {
  if (!state.user) return;
  const u = state.user;
  document.querySelectorAll('.profile-username').forEach(el => el.textContent = u.username);
  document.querySelectorAll('.profile-role').forEach(el => el.textContent = u.role);
  document.querySelectorAll('.profile-initial').forEach(el => el.textContent = u.username[0].toUpperCase());
}
