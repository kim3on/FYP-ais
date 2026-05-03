'use strict';

// ══════════════════════════════════════════════════════════
//  CHARTS — canvas drawing (traffic line + scatter)
// ══════════════════════════════════════════════════════════

// Local chart data buffers (populated from liveChart in capture.js
// or from tdata when no live capture is running)
const tdata = { n: Array(50).fill(0), a: Array(50).fill(0) };

function cssvar(v) {
  return getComputedStyle(document.documentElement).getPropertyValue(v).trim();
}

function drawTrafficChart() {
  const c = document.getElementById('traffic-chart');
  if (!c || !c.offsetWidth) return;
  c.width = c.offsetWidth; c.height = 155;

  const useLive = state.captureRunning ||
    liveChart.normal.some(v => v > 0) ||
    liveChart.anomaly.some(v => v > 0);
  const n_arr = useLive ? liveChart.normal  : tdata.n;
  const a_arr = useLive ? liveChart.anomaly : tdata.a;

  const ctx = c.getContext('2d'), W = c.width, H = c.height, n = n_arr.length, mx = 155;
  ctx.clearRect(0, 0, W, H);
  ctx.strokeStyle = cssvar('--chart-grid'); ctx.lineWidth = 1;
  for (let i = 1; i <= 3; i++) {
    ctx.beginPath(); ctx.moveTo(0, H * i / 4); ctx.lineTo(W, H * i / 4); ctx.stroke();
  }

  // Normal area + line
  ctx.beginPath();
  n_arr.forEach((v, i) => {
    const x = (i / (n - 1)) * W, y = H - (v / mx) * H;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.lineTo(W, H); ctx.lineTo(0, H); ctx.closePath();
  ctx.fillStyle = cssvar('--chart-area'); ctx.fill();

  ctx.beginPath(); ctx.strokeStyle = '#2563EB'; ctx.lineWidth = 2; ctx.lineJoin = 'round';
  n_arr.forEach((v, i) => {
    const x = (i / (n - 1)) * W, y = H - (v / mx) * H;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Anomaly spikes
  a_arr.forEach((v, i) => {
    if (v > 0) {
      const x = (i / (n - 1)) * W, y = H - (v / mx) * H;
      ctx.beginPath(); ctx.strokeStyle = '#DC2626'; ctx.lineWidth = 1.5;
      ctx.moveTo(x, H); ctx.lineTo(x, y); ctx.stroke();
      ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2);
      ctx.fillStyle = '#DC2626'; ctx.fill();
    }
  });
}

function tickChart() {
  if (document.getElementById('panel-dashboard').classList.contains('active')) {
    drawTrafficChart();
  }
}

function drawScatter() {
  const c = document.getElementById('scatter-canvas');
  if (!c || !c.offsetWidth) return;
  c.width = c.offsetWidth; c.height = 155;
  const ctx = c.getContext('2d'), W = c.width, H = c.height;
  ctx.clearRect(0, 0, W, H);

  ctx.strokeStyle = cssvar('--chart-grid'); ctx.lineWidth = 1;
  for (let i = 1; i <= 7; i++) {
    ctx.beginPath(); ctx.moveTo(i * W / 8, 0); ctx.lineTo(i * W / 8, H); ctx.stroke();
  }
  for (let i = 1; i <= 4; i++) {
    ctx.beginPath(); ctx.moveTo(0, i * H / 5); ctx.lineTo(W, i * H / 5); ctx.stroke();
  }

  const hasLiveData = liveChart.normal.some(v => v > 0) || liveChart.anomaly.some(v => v > 0);
  if (!hasLiveData) {
    ctx.font = '12px "DM Mono", monospace';
    ctx.fillStyle = cssvar('--text-tertiary');
    ctx.textAlign = 'center';
    ctx.fillText('No live data — start packet capture or run batch detection', W / 2, H / 2 - 8);
    ctx.font = '10px "DM Mono", monospace';
    ctx.fillText('Detector space will visualise here once data is available', W / 2, H / 2 + 12);
    ctx.textAlign = 'left';
    return;
  }

  const cx = W * 0.38, cy = H * 0.5;
  ctx.beginPath(); ctx.arc(cx, cy, Math.min(W, H) * 0.28, 0, Math.PI * 2);
  ctx.strokeStyle = cssvar('--scatter-ab-stroke'); ctx.lineWidth = 1; ctx.stroke();
  ctx.fillStyle = cssvar('--scatter-ab-fill'); ctx.fill();

  const n = liveChart.normal.length;
  liveChart.normal.forEach((v, i) => {
    if (v <= 0) return;
    const angle = (i / n) * Math.PI * 2;
    const r = Math.min(W, H) * 0.22 * (v / 140);
    const x = cx + Math.cos(angle) * r, y = cy + Math.sin(angle) * r;
    ctx.beginPath(); ctx.arc(x, y, 2.5, 0, Math.PI * 2);
    ctx.fillStyle = cssvar('--scatter-self'); ctx.fill();
  });

  liveChart.anomaly.forEach((v, i) => {
    if (v <= 0) return;
    const angle = (i / n) * Math.PI * 2;
    const r = Math.min(W, H) * 0.38 + (v / 80) * Math.min(W, H) * 0.12;
    const x = cx + Math.cos(angle) * r, y = cy + Math.sin(angle) * r;
    ctx.beginPath(); ctx.arc(x, y, 4, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(220,38,38,0.85)'; ctx.fill();
    ctx.beginPath(); ctx.arc(x, y, 8, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(220,38,38,0.22)'; ctx.lineWidth = 1.5; ctx.stroke();
  });

  ctx.font = '10px "DM Mono",monospace';
  ctx.fillStyle = cssvar('--text-tertiary');
  ctx.fillText('Feature Space — PCA Dimension 1', W / 2 - 88, H - 5);
}

function setScatterView(view, btn) {
  document.querySelectorAll('#panel-dashboard .tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('scatter-visual').style.display = view === 'visual' ? 'block' : 'none';
  document.getElementById('scatter-list').style.display   = view === 'list'   ? 'block' : 'none';
  if (view === 'visual') setTimeout(drawScatter, 50);
}
