'use strict';

// ══════════════════════════════════════════════════════════
//  AUTH — login / logout
// ══════════════════════════════════════════════════════════
async function doLogin() {
  const u = document.getElementById('login-user').value.trim();
  const p = document.getElementById('login-pass').value.trim();
  if (!u || !p) return;

  const btn = document.querySelector('.btn-login-submit');
  btn.textContent = 'Signing in…';
  btn.disabled = true;

  try {
    const data = await api.post('/api/auth/login', { username: u, password: p });
    api._token = data.token;
    state.user = { username: data.username, role: data.role };

    // Update profile display
    document.querySelectorAll('.u-name').forEach(el => el.textContent = data.username);
    document.querySelectorAll('.u-role').forEach(el => el.textContent = data.role);
    document.querySelectorAll('.av-lg').forEach(el => el.textContent = data.username[0].toUpperCase());

    document.getElementById('page-login').classList.remove('active');
    document.getElementById('page-app').classList.add('active');
    initApp();
  } catch {
    toast('Invalid username or password', 'error');
  } finally {
    btn.textContent = 'Sign In';
    btn.disabled = false;
  }
}

function doLogout() {
  api._token = null;
  state.user = null;
  clearInterval(state.statsPoller);
  clearInterval(state.logPoller);
  document.getElementById('page-app').classList.remove('active');
  document.getElementById('page-login').classList.add('active');
}

// Enter key triggers login
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && document.getElementById('page-login').classList.contains('active')) {
    doLogin();
  }
});
