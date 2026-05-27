import { useApp } from '../../hooks/useApp';
import chartArrowRiseIcon from '../../assets/chart-arrow-rise.svg';
import databaseIcon from '../../assets/database.svg';
import shieldIcon from '../../assets/shield.svg';
import { MetricLabel, SummaryIcon } from './shared';


function metricValue(value, digits = 4) {
  if (value == null || Number.isNaN(Number(value))) return '—';
  return Number(value).toFixed(digits);
}

function percentValue(value, digits = 1) {
  if (value == null || Number.isNaN(Number(value))) return '—';
  return `${(Number(value) * 100).toFixed(digits)}%`;
}

function countValue(value) {
  if (value == null || Number.isNaN(Number(value))) return '—';
  return Number(value).toLocaleString();
}

function labelledValue(modelRecord, key) {
  const labelled = modelRecord?.labelled_verification;
  return labelled?.available ? labelled[key] : null;
}

function buildComparisonRecord(trainResult) {
  if (trainResult.comparison_record) return trainResult.comparison_record;
  const nsaCalibration = trainResult.nsa_calibration_summary || trainResult.calibration_summary || trainResult.nsa_summary?.calibration || {};
  const isoCalibration = trainResult.iso_calibration_summary || trainResult.iso_summary?.threshold_calibration || {};
  return {
    run_id: trainResult.run_id,
    trained_at: trainResult.trained_at,
    target_fpr: nsaCalibration.target_fpr ?? isoCalibration.target_fpr,
    models: {
      nsa: {
        mature_detectors: trainResult.nsa_summary?.mature_detectors,
        observed_benign_fpr: nsaCalibration.observed_fpr ?? trainResult.nsa_eval?.false_positive_rate,
        normal_pass_rate: nsaCalibration.normal_pass_rate,
        silhouette: trainResult.nsa_eval?.silhouette?.value ?? trainResult.nsa_eval?.silhouette_score,
        labelled_verification: trainResult.post_run_labelled_verification,
      },
      isolation_forest: {
        estimators: trainResult.iso_summary?.n_estimators,
        contamination: trainResult.iso_summary?.contamination,
        observed_benign_fpr: isoCalibration.observed_fpr ?? trainResult.iso_eval?.false_positive_rate,
        normal_pass_rate: isoCalibration.normal_pass_rate,
        silhouette: trainResult.iso_eval?.silhouette?.value ?? trainResult.iso_eval?.silhouette_score,
        labelled_verification: trainResult.iso_post_run_labelled_verification,
      },
    },
  };
}

function ComparisonPanel({ record }) {
  const nsa = record?.models?.nsa || {};
  const iso = record?.models?.isolation_forest || {};
  const rows = [
    ['Observed Benign FPR', nsa.observed_benign_fpr, iso.observed_benign_fpr, 'percent'],
    ['Normal Pass Rate', nsa.normal_pass_rate, iso.normal_pass_rate, 'percent'],
    ['Silhouette Score', nsa.silhouette, iso.silhouette, 'number'],
    ['Label Recall', labelledValue(nsa, 'recall') ?? labelledValue(nsa, 'true_positive_rate'), labelledValue(iso, 'recall') ?? labelledValue(iso, 'true_positive_rate'), 'percent'],
    ['Label F1', labelledValue(nsa, 'f1'), labelledValue(iso, 'f1'), 'percent'],
  ].filter(([, nsaValue, isoValue]) => nsaValue != null || isoValue != null);

  if (!rows.length) return null;

  const format = (value, type) => {
    if (type === 'percent') return percentValue(value, 1);
    if (type === 'number') return metricValue(value, 3);
    return value ?? '—';
  };

  return (
    <div className="td-comparison-panel">
      <div className="td-section-label">Latest NSA vs IsoFor Comparison</div>
      <div className="td-comparison-meta">
        Run {record.run_id || 'latest'} · Target FPR {percentValue(record.target_fpr, 1)}
      </div>
      <div className="td-comparison-table-wrap">
        <table className="td-comparison-table">
          <thead>
            <tr>
              <th>Metric</th>
              <th>NSA</th>
              <th>IsoFor</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([label, nsaValue, isoValue, type]) => (
              <tr key={label}>
                <td>{label}</td>
                <td>{format(nsaValue, type)}</td>
                <td>{format(isoValue, type)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}


// ══════════════════════════════════════════════════════════════
//  GLOBAL TRAINING RESULT
// ══════════════════════════════════════════════════════════════
export default function GlobalTrainingResult() {
  const { trainResult, trainFile, activeModel } = useApp();
  if (!trainResult) return null;

  const selectedModel = activeModel === 'isolation_forest' ? 'isolation_forest' : 'nsa';
  const isIso = selectedModel === 'isolation_forest';
  const comparisonRecord = buildComparisonRecord(trainResult);
  const modelRecord = comparisonRecord.models?.[selectedModel] || {};
  const nsaSummary = trainResult.nsa_summary || {};
  const isoSummary = trainResult.iso_summary || {};
  const activeCalibration = isIso
    ? (trainResult.iso_calibration_summary || isoSummary.threshold_calibration || {})
    : (trainResult.nsa_calibration_summary || trainResult.calibration_summary || nsaSummary.calibration || {});
  const activeEval = isIso ? (trainResult.iso_eval || {}) : (trainResult.nsa_eval || {});

  let datasetName;
  if (trainResult.dataset_display) {
    datasetName = trainResult.dataset_display;
  } else if (trainFile?.name) {
    datasetName = trainFile.name.replace(/\.[^/.]+$/, '');
  } else if (nsaSummary.dataset_name || isoSummary.dataset_name) {
    datasetName = nsaSummary.dataset_name || isoSummary.dataset_name;
  } else {
    datasetName = 'Loaded Model';
  }

  const observedFpr = activeCalibration.observed_fpr ?? modelRecord.observed_benign_fpr ?? activeEval.false_positive_rate;
  const normalPassRate = activeCalibration.normal_pass_rate ?? modelRecord.normal_pass_rate ?? (observedFpr != null ? 1 - observedFpr : null);
  const targetFpr = activeCalibration.target_fpr ?? comparisonRecord.target_fpr;
  const silhouette = activeEval.silhouette?.value ?? activeEval.silhouette_score ?? modelRecord.silhouette;
  const trainingRows = isIso
    ? (isoSummary.n_training_samples ?? trainResult.split_sizes?.benign_train)
    : (nsaSummary.n_self_samples ?? trainResult.split_sizes?.benign_train);

  const primaryCard = isIso
    ? {
        label: 'Isolation Trees',
        value: countValue(isoSummary.n_estimators ?? modelRecord.estimators),
        subtitle: 'Benign-calibrated baseline',
      }
    : {
        label: 'Active Antibodies',
        value: countValue(nsaSummary.mature_detectors ?? modelRecord.mature_detectors),
        subtitle: 'Valid Detectors Stored',
      };

  const detailMetrics = [
    ['Target FPR', percentValue(targetFpr, 2), 'var(--accent)'],
    ['Observed Benign FPR', percentValue(observedFpr, 2), 'var(--warning)'],
    ['Normal Pass Rate', percentValue(normalPassRate, 2), 'var(--success)'],
    ['Silhouette Score', silhouette != null ? Number(silhouette).toFixed(3) : 'N/A', 'var(--iris)'],
    ...(isIso ? [
      ['Contamination Prior', percentValue(isoSummary.contamination ?? modelRecord.contamination, 2), 'var(--accent)'],
      ['Trees / Estimators', countValue(isoSummary.n_estimators ?? modelRecord.estimators), 'var(--accent)'],
      ['IF Score Threshold', metricValue(activeCalibration.threshold ?? isoSummary.score_threshold ?? modelRecord.threshold), 'var(--text-primary)'],
      ['Score Scale', metricValue(activeCalibration.score_scale ?? isoSummary.score_scale ?? modelRecord.score_scale), 'var(--text-primary)'],
    ] : [
      ['Self Intrusion Rate', percentValue(trainResult.ais_metrics?.self_intrusion_rate ?? activeEval.self_intrusion_rate ?? modelRecord.self_intrusion_rate, 2), 'var(--danger)'],
      ['Fitted Self-Gap Radius', metricValue(nsaSummary.r_fitted ?? nsaSummary.r ?? modelRecord.fitted_r), 'var(--accent)'],
      ['Fitted Detector Tolerance', metricValue(nsaSummary.r_s_fitted ?? nsaSummary.r_s ?? modelRecord.fitted_r_s), 'var(--accent)'],
      ['NSA Self-Gap Threshold', metricValue(activeCalibration.threshold ?? nsaSummary.score_threshold ?? modelRecord.threshold), 'var(--text-primary)'],
    ]),
  ].filter(([, value]) => value !== '—');

  const metricsNote = isIso
    ? 'Fully unsupervised baseline: only BENIGN traffic is used to fit the scaler, PCA, Isolation Forest, and calibrated threshold. Attack labels are report-only.'
    : 'Fully unsupervised: only BENIGN traffic is used to fit the scaler, train AIS detectors, and calibrate the pure NSA self-gap threshold. Attack labels are report-only.';

  return (
    <div style={{ marginBottom: '24px' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginBottom: '12px' }}>
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '12px', padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-h)', fontSize: '11px', fontWeight: 500 }}>
            <SummaryIcon src={shieldIcon} alt="" tone="accent" />
            <MetricLabel label={primaryCard.label} className="td-summary-metric-label" />
          </div>
          <div style={{ fontSize: '22px', fontWeight: 400, color: 'var(--text-h)', fontFamily: "'JetBrains Mono', monospace" }}>
            {primaryCard.value}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--success)', fontFamily: "'JetBrains Mono', monospace" }}>
            {primaryCard.subtitle}
          </div>
        </div>

        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '12px', padding: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-h)', fontSize: '11px', fontWeight: 500 }}>
            <SummaryIcon src={chartArrowRiseIcon} alt="" tone="success" />
            <MetricLabel label="Unsupervised Benign Calibration" className="td-summary-metric-label" />
          </div>
          <div style={{ fontSize: '22px', fontWeight: 400, color: 'var(--text-h)', fontFamily: "'JetBrains Mono', monospace" }}>
            {percentValue(normalPassRate, 2)}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--success)', fontFamily: "'JetBrains Mono', monospace" }}>
            Held-Out BENIGN Calibration
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
            {countValue(trainingRows)} Training Rows
          </div>
        </div>
      </div>

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
          <ComparisonPanel record={comparisonRecord} />
        </div>
      )}
    </div>
  );
}
