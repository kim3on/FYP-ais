import { useState, useRef, useEffect } from 'react';
import {
  startTraining, getTrainingLogs, getTrainingResult,
  detectFromFile, getDetectionLogs, getDetectionResult,
} from '../api';
import { useApp } from '../hooks/useApp';
import AlertTable from '../components/AlertTable';
import '../components/Layout/Layout.css';
import './TrainDetect.css';
import shieldIcon from '../assets/shield.svg';
import chartArrowRiseIcon from '../assets/chart-arrow-rise.svg';
import databaseIcon from '../assets/database.svg';

// ── Shared log box component ───────────────────────────────────
function LogBox({ lines, height = '220px' }) {
  const ref = useRef(null);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [lines]);
  return (
    <div className="log-box" ref={ref} style={{ height }}>
      {lines.length === 0
        ? <span style={{ color: 'var(--text-tertiary)' }}>No output yet…</span>
        : lines.map((l, i) => {
            const cls = /\[OK\]|✓|success/i.test(l) ? 'log-ok'
              : /\[ERR\]|✗|error|fail/i.test(l)    ? 'log-err'
              : /\[WARN\]/i.test(l)                 ? 'log-warn' : 'log-info';
            return <div key={i} className={cls}>{l}</div>;
          })
      }
    </div>
  );
}

// ── FileDropZone ───────────────────────────────────────────────
function FileDropZone({ file, onFile, inputId, icon = '📂' }) {
  const [dragging, setDragging] = useState(false);
  return (
    <>
      <div
        className={`drop-zone ${dragging ? 'drag-over' : ''}`}
        onDragOver={e => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={e => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) onFile(f); }}
        onClick={() => document.getElementById(inputId).click()}
      >
        <div className="drop-icon">{icon}</div>
        {file
          ? <p><span>{file.name}</span><br /><small style={{ color: 'var(--text-tertiary)' }}>{(file.size / 1024 / 1024).toFixed(2)} MB</small></p>
          : <p>Drop a <span>.csv</span> or <span>.parquet</span> file<br /><small style={{ color: 'var(--text-tertiary)' }}>or click to browse</small></p>
        }
      </div>
      <input id={inputId} type="file" accept=".csv,.parquet,.pq" style={{ display: 'none' }} onChange={e => onFile(e.target.files[0])} />
    </>
  );
}

// ── Metrics grid ───────────────────────────────────────────────
function MetricsGrid({ result }) {
  if (!result) return null;
  const rows = [
    ['Accuracy', result.accuracy], ['Precision', result.precision],
    ['Recall', result.recall],     ['F1 Score', result.f1],
    ['False Pos. Rate', result.false_positive_rate],
  ].filter(([, v]) => v != null);
  if (!rows.length) return null;
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '12px' }}>
      {rows.map(([label, val]) => (
        <div key={label} style={{ background: 'var(--bg-overlay)', borderRadius: 'var(--radius)', padding: '10px 12px' }}>
          <div style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-tertiary)', textTransform: 'uppercase', marginBottom: '4px' }}>{label}</div>
          <div style={{ fontSize: '20px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--success)' }}>{(val * 100).toFixed(1)}%</div>
        </div>
      ))}
    </div>
  );
}

function SummaryIcon({ src, alt, tone }) {
  return <img className={`td-summary-icon ${tone || ''}`} src={src} alt={alt} />;
}

// ══════════════════════════════════════════════════════════════
//  TRAINING TAB
// ══════════════════════════════════════════════════════════════
function TrainingTab() {
  const {
    trainFile: file, setTrainFile: setFile,
    nDetectors, setND,
    rRadius, setR,
    rsRadius, setRS,
    trainLogs: logs, setTrainLogs: setLogs,
    setTrainResult: setResult,
    refreshStatus
  } = useApp();

  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState('');
  const pollRef = useRef(null);

  function stopPolling() {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }

  async function handleTrain() {
    if (!file) { setError('Select a dataset file first.'); return; }
    setError(''); setLoading(true); setResult(null);
    setLogs(['[INFO] Starting NSA training pipeline…']);

    try {
      // Start training (returns immediately — backend runs in background)
      const data = await startTraining(file, {
        max_detectors: nDetectors,
        r: rRadius,
        r_s: rsRadius,
      });
      setLogs(prev => [...prev, `[OK] ${data.message || 'Training started'}`]);

      // Poll logs every 1.5s — REPLACE the log array each time (no duplicates)
      pollRef.current = setInterval(async () => {
        try {
          const d = await getTrainingLogs();
          const lines = d.logs || [];
          if (lines.length > 0) setLogs(lines);

          // Stop polling when training finishes
          if (d.status === 'active' || d.status === 'error') {
            stopPolling();
            setLoading(false);

            // Fetch final result
            try {
              const r = await getTrainingResult();
              setResult(r);
            } catch (err) {
              console.error("Failed to fetch training result:", err);
            }
            refreshStatus();
          }
        } catch (err) {
          console.error("Failed to poll training logs:", err);
        }
      }, 1500);

    } catch (err) {
      setLogs(prev => [...prev, `[ERR] ${err.message}`]);
      setError(err.message);
      stopPolling();
      setLoading(false);
    }
  }

  // Fetch existing result on mount & cleanup on unmount
  useEffect(() => {
    getTrainingResult().then(r => { if (r) setResult(r); }).catch(err => {
      console.error("Initial result fetch failed:", err);
    });
    return () => stopPolling();
  }, [setResult]);

  return (
    <div className="tab-body">
      <div className="two-col">
        {/* Left */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div className="card">
            <div className="td-section-label">Dataset — Clean Traffic</div>
            <FileDropZone file={file} onFile={setFile} inputId="train-file" icon="📂" />
          </div>
          <div className="card">
            <div className="td-section-label">NSA Parameters</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>Detectors —</span>
                  <input type="number" value={nDetectors} onChange={e => setND(e.target.value === '' ? '' : Number(e.target.value))} 
                    style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--accent)', width: '80px', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '12px' }} />
                </label>
                <input type="range" min="10" max="20000" step="10" value={nDetectors || 500}
                  onChange={e => setND(Number(e.target.value))}
                  style={{ padding: 0, cursor: 'pointer', accentColor: 'var(--accent)', marginTop: '8px', width: '100%' }} />
              </div>
              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>Self Gap Radius (r) —</span>
                  <input type="number" step="0.01" value={rRadius} onChange={e => setR(e.target.value === '' ? '' : Number(e.target.value))} 
                    style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--accent)', width: '80px', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '12px' }} />
                </label>
                <input type="range" min="0.05" max="1.0" step="0.01" value={rRadius || 0.3}
                  onChange={e => setR(Number(e.target.value))}
                  style={{ padding: 0, cursor: 'pointer', accentColor: 'var(--accent)', marginTop: '8px', width: '100%' }} />
              </div>
              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>Detector Tolerance (r_s) —</span>
                  <input type="number" step="0.01" value={rsRadius} onChange={e => setRS(e.target.value === '' ? '' : Number(e.target.value))} 
                    style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--accent)', width: '80px', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '12px' }} />
                </label>
                <input type="range" min="0.01" max="0.2" step="0.01" value={rsRadius || 0.03}
                  onChange={e => setRS(Number(e.target.value))}
                  style={{ padding: 0, cursor: 'pointer', accentColor: 'var(--accent)', marginTop: '8px', width: '100%' }} />
              </div>
            </div>
          </div>
          {error && <div className="inline-error">⚠ {error}</div>}
          <button className="btn btn-primary" onClick={handleTrain} disabled={loading || !file}
            style={{ width: '100%', justifyContent: 'center', padding: '10px' }}>
            {loading ? <><span className="spinner" /> Training…</> : '⚙ Start Training'}
          </button>
        </div>
        {/* Right */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div className="card" style={{ flex: 1 }}>
            <div className="td-section-label">Training Log</div>
            <LogBox lines={logs} height="250px" />
          </div>
          {/* Training result moved to top */}
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
//  DETECTION TAB
// ══════════════════════════════════════════════════════════════
function DetectionTab() {
  const {
    detectFile: file, setDetectFile: setFile,
    detectLimit: limit, setDetectLimit: setLimit,
    detectLogs: logs, setDetectLogs: setLogs,
    detectResult: result, setDetectResult: setResult
  } = useApp();

  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');
  const pollRef = useRef(null);

  function stopPolling() {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }

  async function handleDetect() {
    if (!file) { setError('Select a file first.'); return; }
    setError(''); setLoading(true); setResult(null);
    setLogs(['[INFO] Starting batch detection…']);
    try {
      // POST starts detection in background — returns immediately
      await detectFromFile(file, limit);

      // Poll every 1.5s — REPLACE log array each time
      pollRef.current = setInterval(async () => {
        try {
          const d = await getDetectionLogs();
          const lines = d.logs || d || [];
          if (lines.length > 0) setLogs(lines);

          // Stop when backend finishes
          if (d.status === 'done' || d.status === 'error') {
            stopPolling();
            setLoading(false);
            const r = await getDetectionResult().catch(() => null);
            if (r) setResult(r);
          }
        } catch (err) {
          console.error("Failed to poll detection logs:", err);
        }
      }, 1500);

    } catch (err) {
      setLogs(prev => [...prev, `[ERR] ${err.message}`]);
      setError(err.message);
      stopPolling();
      setLoading(false);
    }
  }

  // Cleanup on unmount
  useEffect(() => () => stopPolling(), []);

  const alerts    = result?.alerts || [];
  const anomCount = alerts.filter(a => !a.is_false_positive).length;
  const zdCount   = alerts.filter(a => a.is_zero_day || a.attack_type === 'Zero-Day Candidate').length;

  return (
    <div className="tab-body">
      <div className="two-col" style={{ marginBottom: '16px' }}>
        {/* Left */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div className="card">
            <div className="td-section-label">Traffic Log to Analyse</div>
            <FileDropZone file={file} onFile={setFile} inputId="det-file" icon="🔍" />
          </div>
          <div className="card">
            <label>Row Limit — <span style={{ color: 'var(--accent)' }}>{limit.toLocaleString()}</span></label>
            <input type="range" min="100" max="10000" step="100" value={limit}
              onChange={e => setLimit(+e.target.value)}
              style={{ padding: 0, cursor: 'pointer', accentColor: 'var(--accent)', marginTop: '8px' }} />
          </div>
          {error && <div className="inline-error">⚠ {error}</div>}
          <button className="btn btn-primary" onClick={handleDetect} disabled={loading || !file}
            style={{ width: '100%', justifyContent: 'center', padding: '10px' }}>
            {loading ? <><span className="spinner" /> Detecting…</> : '⬢ Run Detection'}
          </button>
          <div className="card">
            <div className="td-section-label">Detection Log</div>
            <LogBox lines={logs} height="160px" />
          </div>
        </div>
        {/* Right — stats */}
        {result && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div className="stat-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
              <div className="stat-card">
                <div className="stat-label">Total Flows</div>
                <div className="stat-value">{result.total_flows ?? alerts.length}</div>
              </div>
              <div className="stat-card" style={{ borderColor: anomCount > 0 ? 'var(--danger-border)' : 'var(--border)' }}>
                <div className="stat-label" style={{ color: 'var(--danger)' }}>Anomalies</div>
                <div className="stat-value" style={{ color: anomCount > 0 ? 'var(--danger)' : 'var(--text-primary)' }}>{anomCount}</div>
              </div>
              {zdCount > 0 && (
                <div className="stat-card" style={{ borderColor: 'var(--iris-border)', gridColumn: 'span 2' }}>
                  <div className="stat-label" style={{ color: 'var(--iris)' }}>⚠ Zero-Day Candidates</div>
                  <div className="stat-value" style={{ color: 'var(--iris)' }}>{zdCount}</div>
                </div>
              )}
            </div>
            <div className="card">
              <div className="td-section-label">Model Metrics</div>
              <MetricsGrid result={result} />
              {!result.accuracy && <p style={{ fontSize: '11px', color: 'var(--text-tertiary)', fontFamily: 'var(--font-mono)', marginTop: '8px' }}>Metrics available when dataset contains a Label column</p>}
            </div>
          </div>
        )}
      </div>

      {/* Results table */}
      {alerts.length > 0 && (
        <div className="card">
          <div className="td-section-label">Detection Results — {alerts.length} alerts</div>
          <AlertTable alerts={alerts} />
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
//  GLOBAL TRAINING RESULT
// ══════════════════════════════════════════════════════════════
function GlobalTrainingResult() {
  const { trainResult, trainFile } = useApp();
  if (!trainResult) return null;

  const detectors = trainResult.nsa_summary?.mature_detectors ?? 0;
  const accuracy = trainResult.nsa_eval?.accuracy != null ? (trainResult.nsa_eval.accuracy * 100).toFixed(1) + '%' : '—';
  const samples = trainResult.nsa_summary?.n_self_samples ?? 0;
  
  let datasetName;
  if (trainFile?.name) {
    datasetName = trainFile.name.replace(/\.[^/.]+$/, "");
  } else if (trainResult.nsa_summary?.dataset_name) {
    datasetName = trainResult.nsa_summary.dataset_name;
  } else {
    datasetName = 'Loaded Model';
  }

  const eval_ = trainResult.nsa_eval || {};
  const detailMetrics = [
    ['Precision',     eval_.precision     != null ? (eval_.precision     * 100).toFixed(1) + '%' : '—', 'var(--success)'],
    ['Recall',        eval_.recall        != null ? (eval_.recall        * 100).toFixed(1) + '%' : '—', 'var(--success)'],
    ['F1 Score',      eval_.f1            != null ? (eval_.f1            * 100).toFixed(1) + '%' : '—', 'var(--success)'],
    ['False Pos. Rate', eval_.false_positive_rate != null ? (eval_.false_positive_rate * 100).toFixed(1) + '%' : '—', 'var(--warning)'],
  ].filter(([, v]) => v !== '—');

  return (
    <div style={{ marginBottom: '24px' }}>
      {/* ── 3 big summary cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginBottom: '12px' }}>
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '12px', padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-h)', fontSize: '11px', fontWeight: 500 }}>
            <SummaryIcon src={shieldIcon} alt="" tone="accent" /> Active Antibodies
          </div>
          <div style={{ fontSize: '22px', fontWeight: 400, color: 'var(--text-h)', fontFamily: "'JetBrains Mono', monospace" }}>
            {detectors.toLocaleString()}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--success)', fontFamily: "'JetBrains Mono', monospace" }}>
            Valid Detectors Stored
          </div>
        </div>

        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '12px', padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-h)', fontSize: '11px', fontWeight: 500 }}>
            <SummaryIcon src={chartArrowRiseIcon} alt="" tone="success" /> Training Accuracy
          </div>
          <div style={{ fontSize: '22px', fontWeight: 400, color: 'var(--text-h)', fontFamily: "'JetBrains Mono', monospace" }}>
            {accuracy}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--success)', fontFamily: "'JetBrains Mono', monospace" }}>
            Baseline vs Validation Set
          </div>
        </div>

        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '12px', padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-h)', fontSize: '11px', fontWeight: 500 }}>
            <SummaryIcon src={databaseIcon} alt="" tone="iris" /> Current Dataset
          </div>
          <div style={{ fontSize: '22px', fontWeight: 400, color: 'var(--text-h)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: "'JetBrains Mono', monospace" }}>
            {datasetName}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--success)', fontFamily: "'JetBrains Mono', monospace" }}>
            {samples.toLocaleString()} Records Loaded
          </div>
        </div>
      </div>

      {/* ── Compact detail metrics ── */}
      {detailMetrics.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(120px, 1fr))', gap: '8px' }}>
          {detailMetrics.map(([label, val, color]) => (
            <div key={label} style={{ background: 'var(--bg-overlay)', borderRadius: 'var(--radius)', padding: '6px 12px', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '8px', fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '2px' }}>{label}</div>
              <div style={{ fontSize: '11px', fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", color }}>{typeof val === 'number' ? val.toLocaleString() : val}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
//  MAIN PAGE — Tab switcher
// ══════════════════════════════════════════════════════════════
export default function TrainDetect() {
  const [tab, setTab] = useState('train');
  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Train & Detect</h1>
        <p className="page-subtitle">Train the NSA Self profile · Run batch anomaly detection</p>
      </div>

      <GlobalTrainingResult />

      {/* Tab bar */}
      <div className="td-tabs">
        <button className={`td-tab ${tab === 'train' ? 'active' : ''}`} onClick={() => setTab('train')}>
          <span>⚙</span> Training
        </button>
        <button className={`td-tab ${tab === 'detect' ? 'active' : ''}`} onClick={() => setTab('detect')}>
          <span>⬢</span> Detection
        </button>
      </div>

      {tab === 'train'  && <TrainingTab />}
      {tab === 'detect' && <DetectionTab />}
    </div>
  );
}
