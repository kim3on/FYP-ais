import { useEffect, useRef, useState } from 'react';
import { detectFromFile, getDetectionLogs, getDetectionResult } from '../../api';
import AlertTable from '../../components/AlertTable';
import { useApp } from '../../hooks/useApp';
import { initializeNotificationSound, playCompletionSound } from '../../utils/notificationSound';
import { DATASET_OPTIONS } from './constants';
import { DatasetSelector, FileDropZone, LogBox, MetricLabel, MetricsGrid } from './shared';


const MAX_DISPLAY_ALERTS = 500;


function DetectionResultPanel({ result, loading }) {
  const alerts = result?.alerts || [];
  const totalFlows = result?.total_checked ?? result?.total_flows ?? result?.alerts_total ?? alerts.length;
  const anomCount = result ? (result.anomalies_found ?? result.alerts_total ?? alerts.filter(a => !a.is_false_positive).length) : null;

  return (
    <div className="td-result-panel">
      <div className="stat-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className={`stat-card ${!result ? 'td-skeleton-card' : ''}`}>
          <MetricLabel label="Total Flows" className="stat-label" />
          <div className="stat-value">{result ? totalFlows.toLocaleString() : '—'}</div>
        </div>
        <div className={`stat-card ${!result ? 'td-skeleton-card' : ''}`} style={{ borderColor: anomCount > 0 ? 'var(--danger-border)' : 'var(--border)' }}>
          <MetricLabel label="Anomalies" className="stat-label danger-label" />
          <div className="stat-value" style={{ color: anomCount > 0 ? 'var(--danger)' : 'var(--text-primary)' }}>
            {result ? anomCount.toLocaleString() : '—'}
          </div>
        </div>
      </div>
      <div className={`card ${!result ? 'td-result-placeholder' : ''}`}>
        <div className="td-section-label">
          {result?.accuracy != null ? 'Post-run Labelled Verification' : 'Unsupervised Detection Summary'}
        </div>
        {result ? (
          <>
            <MetricsGrid result={result} />
            {result.accuracy != null ? (
              <p className="td-detail-note" style={{ marginTop: '8px' }}>
                Verification only: labels were used after detection to score the unsupervised output.
              </p>
            ) : (
              <p className="td-detail-note" style={{ marginTop: '8px' }}>
                Labelled verification appears only when the uploaded detection file contains a Label column.
              </p>
            )}
          </>
        ) : (
          <div className="td-result-skeleton">
            <div className="td-skeleton-line wide" />
            <div className="td-skeleton-grid">
              <div />
              <div />
              <div />
              <div />
            </div>
            <p className="td-detail-note">
              {loading ? 'Detection is running. Results will populate here when the backend completes.' : 'No detection result yet. Run detection to populate this panel.'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
//  DETECTION TAB
// ══════════════════════════════════════════════════════════════
export default function DetectionTab({ canOperate = true }) {
  const {
    detectFile: file, setDetectFile: setFile,
    detectLimit: limit, setDetectLimit: setLimit,
    detectOffset: offset, setDetectOffset: setOffset,
    detectLogs: logs, setDetectLogs: setLogs,
    detectResult: result, setDetectResult: setResult,
    datasetType, setDatasetType
  } = useApp();

  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');
  const pollRef = useRef(null);

  function stopPolling() {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }

  async function handleDetect() {
    if (!canOperate) { setError('Administrator role required to run detection.'); return; }
    if (!file) { setError('Select a file first.'); return; }
    const confirmed = window.confirm(
      `Run detection on "${file.name}"?\n\nRows: ${offset.toLocaleString()}-${(offset + limit).toLocaleString()}`
    );
    if (!confirmed) return;
    initializeNotificationSound();
    setError(''); setLoading(true); setResult(null);
    setLogs(['[INFO] Starting batch detection…']);
    try {
      // POST starts detection in background — returns immediately
      await detectFromFile(file, limit, offset, {
        dataset_type: datasetType,
      });

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
            const r = await getDetectionResult({ alertsLimit: MAX_DISPLAY_ALERTS }).catch(() => null);
            if (r) setResult(r);
            playCompletionSound(d.status === 'error' ? 'error' : 'success');
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

  // Fetch existing result on mount & cleanup on unmount
  useEffect(() => {
    let active = true;
    getDetectionResult({ alertsLimit: MAX_DISPLAY_ALERTS }).then(r => {
      if (active && r) setResult(r);
    }).catch(() => {});
    return () => {
      active = false;
      stopPolling();
    };
  }, [setResult]);

  const alerts    = result?.alerts || [];
  const totalAlerts = result?.alerts_total ?? alerts.length;
  const displayedAlerts = alerts.slice(0, MAX_DISPLAY_ALERTS);
  const datasetOption = DATASET_OPTIONS.find(o => o.id === datasetType) || DATASET_OPTIONS[0];

  return (
    <div className="tab-body">
      <div className="two-col" style={{ marginBottom: '16px' }}>
        {/* Left */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div className="card">
            <div className="td-section-label">Dataset Profile</div>
            <DatasetSelector value={datasetType} onChange={setDatasetType} disabled={!canOperate} />
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
              disabled={!canOperate}
            />
          </div>
          <div className="card">
            <label>Start Row — <span style={{ color: 'var(--accent)' }}>{offset.toLocaleString()}</span></label>
            <input type="number" min="0" step="1000" value={offset}
              disabled={!canOperate}
              onChange={e => setOffset(Math.max(0, Number(e.target.value) || 0))}
              style={{ marginTop: '8px', marginBottom: '12px' }} />
            <label>Rows to Analyse — <span style={{ color: 'var(--accent)' }}>{limit.toLocaleString()}</span></label>
            <input type="range" min="100" max="50000" step="100" value={limit}
              disabled={!canOperate}
              onChange={e => setLimit(+e.target.value)}
              style={{ padding: 0, cursor: 'pointer', accentColor: 'var(--accent)', marginTop: '8px', width: '100%' }} />
            <p className="td-detail-note" style={{ marginTop: '8px' }}>
              Analysing rows {offset.toLocaleString()}–{(offset + limit).toLocaleString()}.
            </p>
          </div>
          {error && <div className="inline-error">⚠ {error}</div>}
          <button className="btn btn-primary" onClick={handleDetect} disabled={loading || !file || !canOperate}
            style={{ width: '100%', justifyContent: 'center', padding: '10px' }}>
            {!canOperate ? 'Admin Only' : loading ? <><span className="spinner" /> Detecting…</> : '⬢ Run Detection'}
          </button>
          <div className="card">
            <div className="td-section-label">Detection Log</div>
            <LogBox lines={logs} height="160px" />
          </div>
        </div>
        {/* Right — stats */}
        <DetectionResultPanel result={result} loading={loading} />
      </div>

      {/* Results table */}
      <div className="card">
        <div className="td-section-label">Detection Results — {totalAlerts.toLocaleString()} alerts</div>
        {result?.alerts_truncated && (
          <p className="td-detail-note" style={{ marginBottom: '10px' }}>
            Showing first {displayedAlerts.length.toLocaleString()} alerts to keep the browser responsive. Full alert history remains in the backend and Alerts page pagination.
          </p>
        )}
        {displayedAlerts.length > 0 ? (
          <AlertTable alerts={displayedAlerts} />
        ) : (
          <div className="td-empty-results">
            {loading ? 'Waiting for detection output...' : 'No detection alerts to display yet.'}
          </div>
        )}
      </div>
    </div>
  );
}
