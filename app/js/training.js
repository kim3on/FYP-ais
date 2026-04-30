'use strict';

// ══════════════════════════════════════════════════════════
//  TRAINING — upload dataset + log polling
// ══════════════════════════════════════════════════════════

function triggerFilePick() {
  document.getElementById('train-file-input').click();
}

function onFileSelected(input) {
  const file = input.files[0];
  if (!file) return;
  state.trainingFile = file;

  const isParquet = file.name.endsWith('.parquet') || file.name.endsWith('.pq');
  const sizeMB = (file.size / 1048576).toFixed(2);
  const ext    = isParquet ? 'Parquet' : 'CSV';

  const zone = document.getElementById('upload-zone');
  zone.style.borderColor = 'var(--success)';
  zone.style.background  = 'var(--success-subtle)';
  zone.innerHTML = `
    <div class="upload-ico" style="background:var(--success-subtle);color:var(--success);">
      <svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5">
        <path d="M4.5 9l3.5 3.5L14 5"/><circle cx="9" cy="9" r="8"/>
      </svg>
    </div>
    <div class="upload-main" style="color:var(--success)">${file.name}</div>
    <div class="upload-sub">${ext} · ${sizeMB} MB · ready to train</div>`;
  zone.style.cursor = 'default';

  setText('train-dataset-name',    isParquet ? 'CIC-IDS2017' : file.name.replace(/\.[^.]+$/, ''));
  setText('train-dataset-records', `${sizeMB} MB · awaiting training`);

  const logEl = document.getElementById('training-log');
  const ts = new Date().toISOString().substr(11, 8);
  logEl.innerHTML = `<div><span class="log-ts">[${ts}]</span><span class="log-info">File selected: ${file.name} (${ext}, ${sizeMB} MB). Ready to train.</span></div>`;
}

async function startTraining() {
  if (state.trainingActive) return;
  if (!state.trainingFile) { toast('Please select a training dataset first', 'warning'); return; }
  if (!state.backendOnline) { toast('Backend is offline — start the FastAPI server first', 'error'); return; }

  state.trainingActive = true;

  const r           = parseFloat(document.getElementById('train-radius')?.value || '0.5');
  const maxDet      = parseInt(document.getElementById('train-max-detectors')?.value || '500');
  const maxAttempts = parseInt(document.getElementById('train-max-attempts')?.value || '10000');
  const contamination = parseFloat(document.getElementById('train-contamination')?.value || '0.05');

  const logEl = document.getElementById('training-log');
  const fill  = document.getElementById('progress-fill');
  const pct   = document.getElementById('progress-pct');
  const btn   = document.getElementById('btn-start-training');
  const st    = document.getElementById('system-status');

  logEl.innerHTML = ''; fill.style.width = '0%'; pct.textContent = '0%';
  if (btn) { btn.disabled = true; btn.innerHTML = '<span style="font-family:var(--font-mono);font-size:11px;">⏳ Training…</span>'; }
  st.className = 'status-badge learning';
  st.innerHTML = '<div class="status-dot"></div>Learning';

  const appendLog = (line, cls = 'log-info') => {
    const div = document.createElement('div');
    const ts  = new Date().toISOString().substr(11, 8);
    div.innerHTML = `<span class="log-ts">[${ts}]</span><span class="${cls}">${line.replace(/^\[.*?\]\s*/, '')}</span>`;
    logEl.appendChild(div);
    logEl.scrollTop = logEl.scrollHeight;
  };

  const params = new URLSearchParams({ r, max_detectors: maxDet, max_attempts: maxAttempts, contamination }).toString();
  const form   = new FormData();
  form.append('file', state.trainingFile);

  try {
    await api.postForm(`/api/train?${params}`, form);
    toast('Training started — streaming logs…', 'info');
    appendLog('Training pipeline initiated on backend.', 'log-info');

    let lastCount = 0;
    clearInterval(state.logPoller);

    state.logPoller = setInterval(async () => {
      try {
        const { logs, status } = await api.get('/api/train/logs');
        const newLines = logs.slice(lastCount);
        lastCount = logs.length;

        newLines.forEach(line => {
          let cls = 'log-info';
          if (line.includes('[OK]') || line.includes('[COMPLETE]')) cls = 'log-ok';
          else if (line.includes('[WARN]'))  cls = 'log-warn';
          else if (line.includes('[ERROR]')) cls = 'log-err';
          appendLog(line, cls);
          const prog = Math.min(98, Math.round((lastCount / 14) * 100));
          fill.style.width = prog + '%';
          pct.textContent  = prog + '%';
        });

        if (status === 'active') {
          clearInterval(state.logPoller);
          state.trainingActive = false;
          fill.style.width = '100%'; pct.textContent = '100%';
          if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 12 12" fill="none"><polygon points="3,2 10,6 3,10" fill="currentColor"/></svg> Start Training';
          }
          st.className = 'status-badge active';
          st.innerHTML = '<div class="status-dot"></div>System Active';
          toast('Training complete! Stats updated.', 'success');
          await loadTrainingResult();
          fetchDashboardStats();

        } else if (status === 'error') {
          clearInterval(state.logPoller);
          state.trainingActive = false;
          if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 12 12" fill="none"><polygon points="3,2 10,6 3,10" fill="currentColor"/></svg> Retry Training';
          }
          toast('Training failed — check the execution log', 'error');
        }
      } catch { /* keep polling */ }
    }, 700);

  } catch (err) {
    state.trainingActive = false;
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 12 12" fill="none"><polygon points="3,2 10,6 3,10" fill="currentColor"/></svg> Start Training';
    }
    toast(err.message || 'Training request failed', 'error');
  }
}

async function loadTrainingResult() {
  try {
    const result = await api.get('/api/train/result');
    const vs     = result.validation_stats || {};
    const nsa    = result.nsa_eval         || {};
    const nsaSum = result.nsa_summary      || {};

    setText('train-val-total',  vs.total_records  ? vs.total_records.toLocaleString()  : '—');
    setText('train-val-normal', vs.normal_records ? vs.normal_records.toLocaleString() : '—');
    setText('train-val-attack', vs.attack_records ? vs.attack_records.toLocaleString() : '—');

    const antibodies = nsaSum.mature_detectors ?? 0;
    setText('train-antibodies', antibodies.toLocaleString());
    setText('train-accuracy', nsa.accuracy ? (nsa.accuracy * 100).toFixed(1) + '%' : '—');

    const dsName    = vs.dataset || 'Unknown';
    const dsRecords = vs.total_records ? vs.total_records.toLocaleString() + ' records' : 'N/A';
    const nFeats    = vs.n_features ? ` · ${vs.n_features} features` : '';
    setText('train-dataset-name',    dsName);
    setText('train-dataset-records', dsRecords + nFeats);
  } catch { /* No result yet */ }
}
