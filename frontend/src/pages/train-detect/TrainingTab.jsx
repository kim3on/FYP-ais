import { useEffect, useRef, useState } from 'react';
import { getTrainingLogs, getTrainingResult, startTraining } from '../../api';
import { useApp } from '../../hooks/useApp';
import { initializeNotificationSound, playCompletionSound } from '../../utils/notificationSound';
import { DATASET_OPTIONS } from './constants';
import { DatasetSelector, FileDropZone, LogBox, MetricLabel } from './shared';


// ══════════════════════════════════════════════════════════════
//  TRAINING TAB
// ══════════════════════════════════════════════════════════════
export default function TrainingTab({ canOperate = true }) {
  const {
    trainFile: file, setTrainFile: setFile,
    nDetectors, setND,
    benignRowLimit, setBenignRowLimit,
    trainTargetFpr, setTrainTargetFpr,
    isoContamination, setIsoContamination,
    isoEstimators, setIsoEstimators,
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
    if (!canOperate) { setError('Administrator role required to start training.'); return; }
    if (!file) { setError('Select a dataset file first.'); return; }
    const confirmed = window.confirm(
      `Start training with "${file.name}"?\n\nTarget FPR: ${(trainTargetFpr * 100).toFixed(1)}%\nNSA detectors: ${Number(nDetectors || 0).toLocaleString()}\nIsoFor trees: ${Number(isoEstimators || 0).toLocaleString()}\nThis may take a while and will replace the current trained models for the selected dataset profile.`
    );
    if (!confirmed) return;
    initializeNotificationSound();
    setError(''); setLoading(true); setResult(null);
    setLogs(['[INFO] Starting unsupervised NSA + Isolation Forest training pipeline...']);

    try {
      // Start training (returns immediately — backend runs in background)
      const data = await startTraining(file, {
        max_detectors: nDetectors || 3000,
        target_fpr: trainTargetFpr,
        contamination: isoContamination || 0.05,
        iso_n_estimators: isoEstimators || 100,
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
            <DatasetSelector value={datasetType} onChange={setDatasetType} disabled={!canOperate} />
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
              disabled={!canOperate}
            />
          </div>
          <div className="card">
            <div className="td-section-label">Shared Calibration</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>BENIGN Rows —</span>
                  <input type="number" min="100" step="1000" value={benignRowLimit}
                    disabled={!canOperate}
                    onChange={e => setBenignRowLimit(e.target.value === '' ? '' : Number(e.target.value))}
                    style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--accent)', width: '100px', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '12px' }} />
                </label>
                <input type="range" min="1000" max="100000" step="1000" value={benignRowLimit || 20000}
                  disabled={!canOperate}
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
                    disabled={!canOperate}
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
                  disabled={!canOperate}
                  onChange={e => setTrainTargetFpr(Number(e.target.value))}
                  style={{ padding: 0, cursor: 'pointer', accentColor: 'var(--accent)', marginTop: '8px', width: '100%' }}
                />
                <p className="td-detail-note" style={{ marginTop: '8px' }}>
                  Shared BENIGN-only calibration for NSA and Isolation Forest. Batch and live detection use this after retraining.
                </p>
              </div>
            </div>
          </div>
          <div className="td-training-param-grid">
            <div className="card">
              <div className="td-section-label">NSA Parameters</div>
              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>Detectors —</span>
                  <input type="number" value={nDetectors} disabled={!canOperate} onChange={e => setND(e.target.value === '' ? '' : Number(e.target.value))}
                    style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--accent)', width: '80px', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '12px' }} />
                </label>
                <input type="range" min="10" max="10000" step="10" value={nDetectors || 3000}
                  disabled={!canOperate}
                  onChange={e => setND(Number(e.target.value))}
                  style={{ padding: 0, cursor: 'pointer', accentColor: 'var(--accent)', marginTop: '8px', width: '100%' }} />
                <p className="td-detail-note" style={{ marginTop: '8px' }}>
                  Mature V-detectors for the AIS/NSA engine only.
                </p>
              </div>
            </div>
            <div className="card">
              <div className="td-section-label">Isolation Forest Parameters</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <MetricLabel label="Contamination Prior" className="td-inline-label" />
                    <input
                      type="number"
                      min="0.001"
                      max="0.20"
                      step="0.001"
                      value={isoContamination}
                      disabled={!canOperate}
                      onChange={e => setIsoContamination(Math.min(0.20, Math.max(0.001, Number(e.target.value) || 0.05)))}
                      style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--accent)', width: '84px', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '12px' }}
                    />
                    <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                      {(isoContamination * 100).toFixed(1)}%
                    </span>
                  </label>
                  <input type="range" min="0.001" max="0.20" step="0.001" value={isoContamination}
                    disabled={!canOperate}
                    onChange={e => setIsoContamination(Number(e.target.value))}
                    style={{ padding: 0, cursor: 'pointer', accentColor: 'var(--accent)', marginTop: '8px', width: '100%' }} />
                </div>
                <div>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span>Trees / Estimators —</span>
                    <input type="number" min="50" max="500" step="10" value={isoEstimators}
                      disabled={!canOperate}
                      onChange={e => setIsoEstimators(e.target.value === '' ? '' : Math.min(500, Math.max(50, Number(e.target.value) || 100)))}
                      style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--accent)', width: '80px', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--font-mono)', fontSize: '12px' }} />
                  </label>
                  <input type="range" min="50" max="500" step="10" value={isoEstimators || 100}
                    disabled={!canOperate}
                    onChange={e => setIsoEstimators(Number(e.target.value))}
                    style={{ padding: 0, cursor: 'pointer', accentColor: 'var(--accent)', marginTop: '8px', width: '100%' }} />
                </div>
                <p className="td-detail-note">
                  IsoFor still uses BENIGN-calibrated thresholding; contamination is retained as the sklearn prior.
                </p>
              </div>
            </div>
          </div>
          {error && <div className="inline-error">⚠ {error}</div>}
          <button className="btn btn-primary" onClick={handleTrain} disabled={loading || !file || !canOperate}
            style={{ width: '100%', justifyContent: 'center', padding: '10px' }}>
            {!canOperate ? 'Admin Only' : loading ? <><span className="spinner" /> Training…</> : '⚙ Start Training'}
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
