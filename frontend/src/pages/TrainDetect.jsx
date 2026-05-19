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

const DATASET_OPTIONS = [
  {
    id: 'cicids2017',
    label: 'CICIDS2017',
    hint: 'Live-compatible flow features',
    accept: '.csv,.parquet,.pq',
    dropText: <>Drop a <span>.csv</span> or <span>.parquet</span> file</>,
  },
  {
    id: 'nsl_kdd',
    label: 'NSL-KDD Benchmark',
    hint: 'Batch-only CSV with headers',
    accept: '.csv',
    dropText: <>Drop a <span>.csv</span> file</>,
  },
];

function DatasetSelector({ value, onChange }) {
  const selected = DATASET_OPTIONS.find(option => option.id === value) || DATASET_OPTIONS[0];
  return (
    <>
      <div className="td-selected-dataset">
        <span>Selected Profile</span>
        <strong>{selected.label}</strong>
      </div>
      <div className="td-dataset-selector">
        {DATASET_OPTIONS.map(option => (
          <button
            key={option.id}
            type="button"
            className={`td-dataset-option ${value === option.id ? 'active' : ''}`}
            aria-pressed={value === option.id}
            onClick={() => onChange(option.id)}
          >
            <span className="td-dataset-option-head">
              <span>{option.label}</span>
              {value === option.id && <strong>Selected</strong>}
            </span>
            <small>{option.hint}</small>
          </button>
        ))}
      </div>
    </>
  );
}

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
function FileDropZone({ file, onFile, inputId, icon = '📂', accept = '.csv,.parquet,.pq', dropText = null }) {
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
          : <p>{dropText || <>Drop a <span>.csv</span> or <span>.parquet</span> file</>}<br /><small style={{ color: 'var(--text-tertiary)' }}>or click to browse</small></p>
        }
      </div>
      <input id={inputId} type="file" accept={accept} style={{ display: 'none' }} onChange={e => onFile(e.target.files[0])} />
    </>
  );
}

// ── Metrics grid ───────────────────────────────────────────────
function MetricsGrid({ result }) {
  if (!result) return null;
  const formatMetric = (label, value) => {
    if (value == null) return '—';
    const pct = value * 100;
    if (/False (Pos|Neg)\. Rate/.test(label) && pct > 0 && pct < 0.01) return '<0.01%';
    return `${pct.toFixed(/False (Pos|Neg)\. Rate/.test(label) ? 2 : 1)}%`;
  };
  const rows = [
    ['Recall / TPR', result.true_positive_rate ?? result.recall],
    ['False Neg. Rate', result.false_negative_rate],
    ['False Pos. Rate', result.false_positive_rate],
    ['Precision', result.precision],
    ['F1 Score', result.f1],
    ['Accuracy (secondary)', result.accuracy],
  ].filter(([, v]) => v != null);
  const unsupervisedRows = rows.length ? [] : [
    ['Anomaly Rate', result.detection_rate_pct != null ? result.detection_rate_pct / 100 : null],
    ['Normal Flows', result.normal_count, 'count'],
    ['Anomalies', result.anomalies_found, 'count'],
    ['Zero-Day Candidates', result.zero_day_candidates, 'count'],
  ].filter(([, v]) => v != null);
  const displayRows = rows.length ? rows : unsupervisedRows;
  const counts = [
    ['TP - Attacks Caught', result.tp],
    ['FN - Attacks Missed', result.fn],
    ['FP - False Alarms', result.fp],
    ['TN - Normal Passed', result.tn],
  ].filter(([, v]) => v != null);
  if (!displayRows.length) return null;
  return (
    <div className="td-model-metrics">
      <div className="td-metric-grid">
        {displayRows.map(([label, val, type]) => (
          <div key={label} className="td-model-metric">
            <div className="td-detail-label">{label}</div>
            <div className="td-model-metric-value">{type === 'count' ? val.toLocaleString() : formatMetric(label, val)}</div>
          </div>
        ))}
      </div>

      {counts.length > 0 && (
        <div className="td-confusion-grid">
          {counts.map(([label, val]) => (
            <div key={label} className="td-confusion-row">
              <span>{label}</span>
              <strong>{val.toLocaleString()}</strong>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ThresholdSummary({ analysis }) {
  const rec = analysis?.recommended;
  if (!analysis?.available || !rec) return null;
  const pct = value => value != null ? `${(value * 100).toFixed(1)}%` : '—';
  return (
    <div className="td-threshold-summary">
      <div className="td-section-label">Threshold Tradeoff Summary</div>
      <div className="td-detail-note">
        Report-only recommendation. It does not change the saved unsupervised model threshold.
      </div>
      <div className="td-detail-metrics">
        <div className="td-detail-metric">
          <div className="td-detail-label">Recommended Threshold</div>
          <div className="td-detail-value">{rec.threshold?.toFixed ? rec.threshold.toFixed(4) : rec.threshold}</div>
        </div>
        <div className="td-detail-metric">
          <div className="td-detail-label">Recall / TPR</div>
          <div className="td-detail-value" style={{ color: 'var(--success)' }}>{pct(rec.recall)}</div>
        </div>
        <div className="td-detail-metric">
          <div className="td-detail-label">FNR</div>
          <div className="td-detail-value" style={{ color: 'var(--danger)' }}>{pct(rec.false_negative_rate)}</div>
        </div>
        <div className="td-detail-metric">
          <div className="td-detail-label">FPR</div>
          <div className="td-detail-value" style={{ color: 'var(--warning)' }}>{pct(rec.false_positive_rate)}</div>
        </div>
      </div>
      <p className="td-detail-note" style={{ marginTop: '8px' }}>
        {analysis.target_achieved ? 'Target achieved: ' : 'Best tradeoff found: '}
        {analysis.recommendation_reason}
      </p>
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
    benignRowLimit, setBenignRowLimit,
    rRadius, setR,
    rsRadius, setRS,
    trainLogs: logs, setTrainLogs: setLogs,
    setTrainResult: setResult,
    refreshStatus,
    datasetType, setDatasetType
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
        target_fpr: 0.05,
        dataset_type: datasetType,
        ...(benignRowLimit ? { benign_row_limit: benignRowLimit } : {}),
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

  const datasetOption = DATASET_OPTIONS.find(o => o.id === datasetType) || DATASET_OPTIONS[0];

  return (
    <div className="tab-body">
      <div className="two-col">
        {/* Left */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div className="card">
            <div className="td-section-label">Dataset Profile</div>
            <DatasetSelector value={datasetType} onChange={setDatasetType} />
            {datasetType === 'nsl_kdd' && (
              <p className="td-detail-note" style={{ marginTop: '8px' }}>
                NSL-KDD is an offline benchmark path. Live capture remains CICIDS2017-only.
              </p>
            )}
          </div>
          <div className="card">
            <div className="td-section-label">Dataset — Clean Traffic</div>
            <FileDropZone
              file={file}
              onFile={setFile}
              inputId="train-file"
              icon="📂"
              accept={datasetOption.accept}
              dropText={datasetOption.dropText}
            />
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
                <input type="range" min="10" max="10000" step="10" value={nDetectors || 3000}
                  onChange={e => setND(Number(e.target.value))}
                  style={{ padding: 0, cursor: 'pointer', accentColor: 'var(--accent)', marginTop: '8px', width: '100%' }} />
              </div>
              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>BENIGN Rows —</span>
                  <input type="number" min="100" step="1000" value={benignRowLimit}
                    onChange={e => setBenignRowLimit(e.target.value === '' ? '' : Number(e.target.value))}
                    style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--accent)', width: '100px', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '12px' }} />
                </label>
                <input type="range" min="1000" max="100000" step="1000" value={benignRowLimit || 20000}
                  onChange={e => setBenignRowLimit(Number(e.target.value))}
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
    detectResult: result, setDetectResult: setResult,
    datasetType, setDatasetType
  } = useApp();

  const [offset, setOffset]   = useState(0);
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
      await detectFromFile(file, limit, offset, { dataset_type: datasetType });

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
  const datasetOption = DATASET_OPTIONS.find(o => o.id === datasetType) || DATASET_OPTIONS[0];

  return (
    <div className="tab-body">
      <div className="two-col" style={{ marginBottom: '16px' }}>
        {/* Left */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div className="card">
            <div className="td-section-label">Dataset Profile</div>
            <DatasetSelector value={datasetType} onChange={setDatasetType} />
            {datasetType === 'nsl_kdd' && (
              <p className="td-detail-note" style={{ marginTop: '8px' }}>
                Batch benchmark only. Use the NSL-KDD model trained under the same profile.
              </p>
            )}
          </div>
          <div className="card">
            <div className="td-section-label">Traffic Log to Analyse</div>
            <FileDropZone
              file={file}
              onFile={setFile}
              inputId="det-file"
              icon="🔍"
              accept={datasetOption.accept}
              dropText={datasetOption.dropText}
            />
          </div>
          <div className="card">
            <label>Start Row — <span style={{ color: 'var(--accent)' }}>{offset.toLocaleString()}</span></label>
            <input type="number" min="0" step="1000" value={offset}
              onChange={e => setOffset(Math.max(0, Number(e.target.value) || 0))}
              style={{ marginTop: '8px', marginBottom: '12px' }} />
            <label>Rows to Analyse — <span style={{ color: 'var(--accent)' }}>{limit.toLocaleString()}</span></label>
            <input type="range" min="100" max="50000" step="100" value={limit}
              onChange={e => setLimit(+e.target.value)}
              style={{ padding: 0, cursor: 'pointer', accentColor: 'var(--accent)', marginTop: '8px', width: '100%' }} />
            <p className="td-detail-note" style={{ marginTop: '8px' }}>
              Analysing rows {offset.toLocaleString()}–{(offset + limit).toLocaleString()}.
            </p>
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
                <div className="stat-value">{result.total_checked ?? result.total_flows ?? alerts.length}</div>
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
              <div className="td-section-label">
                {result.accuracy != null ? 'Post-run Labelled Verification' : 'Unsupervised Detection Summary'}
              </div>
              <MetricsGrid result={result} />
              <ThresholdSummary analysis={result.threshold_analysis} />
              {result.accuracy != null ? (
                <p className="td-detail-note" style={{ marginTop: '8px' }}>
                  Verification only: labels were used after detection to score the unsupervised output.
                </p>
              ) : (
                <p className="td-detail-note" style={{ marginTop: '8px' }}>
                  Labelled verification appears only when the uploaded detection file contains a Label column.
                </p>
              )}
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

  const formatPercent = (value, digits = 1) => (value != null ? `${(value * 100).toFixed(digits)}%` : '—');
  const detectors = trainResult.nsa_summary?.mature_detectors ?? 0;
  const samples = trainResult.nsa_summary?.n_self_samples ?? 0;
  
  let datasetName;
  if (trainResult.dataset_display) {
    datasetName = trainResult.dataset_display;
  } else if (trainFile?.name) {
    datasetName = trainFile.name.replace(/\.[^/.]+$/, "");
  } else if (trainResult.nsa_summary?.dataset_name) {
    datasetName = trainResult.nsa_summary.dataset_name;
  } else {
    datasetName = 'Loaded Model';
  }

  const eval_ = trainResult.nsa_eval || {};
  const calibration = trainResult.calibration_summary || trainResult.nsa_summary?.calibration || {};
  const targetFpr = calibration.target_fpr ?? trainResult.nsa_summary?.target_fpr;
  const observedFpr = calibration.observed_fpr ?? eval_.false_positive_rate;
  const selfIntrusionRate = trainResult.ais_metrics?.self_intrusion_rate ?? eval_.self_intrusion_rate;
  const silhouette = trainResult.unsupervised_validation?.silhouette ?? eval_.silhouette;
  const normalPassRate = calibration.normal_pass_rate ?? (1 - (observedFpr ?? 0));
  const accuracyTitle = 'Unsupervised Benign Calibration';
  const accuracyValue = formatPercent(normalPassRate, 2);
  const accuracySubtitle = 'Held-Out BENIGN Calibration';
  const detailMetrics = [
    ['Target FPR', formatPercent(targetFpr, 2), 'var(--accent)'],
    ['Observed Benign FPR', formatPercent(observedFpr, 2), 'var(--warning)'],
    ['Self Intrusion Rate', formatPercent(selfIntrusionRate, 2), 'var(--danger)'],
    ['Normal Pass Rate', formatPercent(normalPassRate, 2), 'var(--success)'],
    ['Silhouette Score', silhouette?.value != null ? silhouette.value.toFixed(3) : 'N/A', 'var(--iris)'],
    ['Threshold', calibration.threshold != null ? calibration.threshold.toFixed(4) : '—', 'var(--text-primary)'],
  ].filter(([, v]) => v !== '—');
  const metricsNote = 'Fully unsupervised: only BENIGN traffic is used to fit the scaler, train AIS detectors, and calibrate the threshold. Attack labels are not used for training.';

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
            <SummaryIcon src={chartArrowRiseIcon} alt="" tone="success" /> {accuracyTitle}
          </div>
          <div style={{ fontSize: '22px', fontWeight: 400, color: 'var(--text-h)', fontFamily: "'JetBrains Mono', monospace" }}>
            {accuracyValue}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--success)', fontFamily: "'JetBrains Mono', monospace" }}>
            {accuracySubtitle}
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
        <div className="td-detail-panel">
          <div className="td-detail-note">{metricsNote}</div>
          <div className="td-detail-metrics">
            {detailMetrics.map(([label, val, color]) => (
              <div key={label} className="td-detail-metric">
                <div className="td-detail-label">{label}</div>
                <div className="td-detail-value" style={{ color }}>{val}</div>
              </div>
            ))}
          </div>
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
        <p className="page-subtitle">Train an unsupervised NSA self profile · Run batch anomaly detection</p>
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
