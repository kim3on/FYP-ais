import { useEffect, useRef, useState } from 'react';
import { getTrainingLogs, getTrainingResult, startTraining } from '../../api';
import { useApp } from '../../hooks/useApp';
import { initializeNotificationSound, playCompletionSound } from '../../utils/notificationSound';
import { DATASET_OPTIONS } from './constants';
import { DatasetSelector, FileDropZone, LogBox, MetricLabel } from './shared';


// ══════════════════════════════════════════════════════════════
//  TRAINING TAB
// ══════════════════════════════════════════════════════════════
export default function TrainingTab() {
  const {
    trainFile: file, setTrainFile: setFile,
    nDetectors, setND,
    benignRowLimit, setBenignRowLimit,
    trainTargetFpr, setTrainTargetFpr,
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
    const confirmed = window.confirm(
      `Start training with "${file.name}"?\n\nTarget FPR: ${(trainTargetFpr * 100).toFixed(1)}%\nThis may take a while and will replace the current trained model for the selected dataset profile.`
    );
    if (!confirmed) return;
    initializeNotificationSound();
    setError(''); setLoading(true); setResult(null);
    setLogs(['[INFO] Starting NSA training pipeline…']);

    try {
      // Start training (returns immediately — backend runs in background)
      const data = await startTraining(file, {
        max_detectors: nDetectors,
        target_fpr: trainTargetFpr,
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
            playCompletionSound(d.status === 'error' ? 'error' : 'success');
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
              <div className="td-training-fpr-control">
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <MetricLabel label="Target FPR" className="td-inline-label" />
                  <input
                    type="number"
                    min="0.01"
                    max="0.20"
                    step="0.01"
                    value={trainTargetFpr}
                    onChange={e => setTrainTargetFpr(Math.min(0.20, Math.max(0.01, Number(e.target.value) || 0.10)))}
                    style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--accent)', width: '80px', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}
                  />
                  <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                    {(trainTargetFpr * 100).toFixed(0)}%
                  </span>
                </label>
                <input
                  type="range"
                  min="0.01"
                  max="0.20"
                  step="0.01"
                  value={trainTargetFpr}
                  onChange={e => setTrainTargetFpr(Number(e.target.value))}
                  style={{ padding: 0, cursor: 'pointer', accentColor: 'var(--accent)', marginTop: '8px', width: '100%' }}
                />
                <p className="td-detail-note" style={{ marginTop: '8px' }}>
                  Calibrates the saved benign threshold during training. Batch and live detection use this after retraining.
                </p>
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
