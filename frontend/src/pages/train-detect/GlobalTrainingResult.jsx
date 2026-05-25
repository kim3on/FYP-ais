import { useApp } from '../../hooks/useApp';
import chartArrowRiseIcon from '../../assets/chart-arrow-rise.svg';
import databaseIcon from '../../assets/database.svg';
import shieldIcon from '../../assets/shield.svg';
import { MetricLabel, SummaryIcon } from './shared';


// ══════════════════════════════════════════════════════════════
//  GLOBAL TRAINING RESULT
// ══════════════════════════════════════════════════════════════
export default function GlobalTrainingResult() {
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
  const fittedR = trainResult.nsa_summary?.r_fitted ?? trainResult.nsa_summary?.r;
  const fittedRS = trainResult.nsa_summary?.r_s_fitted ?? trainResult.nsa_summary?.r_s;
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
    ['Fitted Self-Gap Radius', fittedR != null ? Number(fittedR).toFixed(4) : '—', 'var(--accent)'],
    ['Fitted Detector Tolerance', fittedRS != null ? Number(fittedRS).toFixed(4) : '—', 'var(--accent)'],
    ['NSA Self-Gap Threshold', calibration.threshold != null ? calibration.threshold.toFixed(4) : '—', 'var(--text-primary)'],
  ].filter(([, v]) => v !== '—');
  const metricsNote = 'Fully unsupervised: only BENIGN traffic is used to fit the scaler, train AIS detectors, and calibrate the pure NSA self-gap threshold. Attack labels are not used for training.';

  return (
    <div style={{ marginBottom: '24px' }}>
      {/* ── 3 big summary cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginBottom: '12px' }}>
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '12px', padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-h)', fontSize: '11px', fontWeight: 500 }}>
            <SummaryIcon src={shieldIcon} alt="" tone="accent" />
            <MetricLabel label="Active Antibodies" className="td-summary-metric-label" />
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
            <SummaryIcon src={chartArrowRiseIcon} alt="" tone="success" />
            <MetricLabel label={accuracyTitle} className="td-summary-metric-label" />
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
            <SummaryIcon src={databaseIcon} alt="" tone="iris" />
            <MetricLabel label="Current Dataset" className="td-summary-metric-label" />
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
                <MetricLabel label={label} />
                <div className="td-detail-value" style={{ color }}>{val}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
