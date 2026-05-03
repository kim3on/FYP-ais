'use strict';

// ══════════════════════════════════════════════════════════
//  CONFIG
// ══════════════════════════════════════════════════════════
const API = 'http://localhost:8000';

// ══════════════════════════════════════════════════════════
//  API CLIENT
// ══════════════════════════════════════════════════════════
const api = {
  _token: null,

  _headers() {
    const h = { 'Content-Type': 'application/json' };
    if (this._token) h['Authorization'] = `Bearer ${this._token}`;
    return h;
  },

  async get(path) {
    const r = await fetch(API + path, { headers: this._headers() });
    if (!r.ok) throw new Error(`GET ${path} → ${r.status}`);
    return r.json();
  },

  async post(path, body) {
    const r = await fetch(API + path, {
      method: 'POST',
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`POST ${path} → ${r.status}`);
    return r.json();
  },

  async postForm(path, formData) {
    const h = {};
    if (this._token) h['Authorization'] = `Bearer ${this._token}`;
    const r = await fetch(API + path, { method: 'POST', headers: h, body: formData });
    if (!r.ok) {
      const err = await r.json().catch(() => ({ detail: r.statusText }));
      throw new Error(err.detail || `POST ${path} → ${r.status}`);
    }
    return r.json();
  },

  async patch(path, body) {
    const r = await fetch(API + path, {
      method: 'PATCH',
      headers: this._headers(),
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`PATCH ${path} → ${r.status}`);
    return r.json();
  },
};
