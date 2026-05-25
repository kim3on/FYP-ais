import { useEffect, useRef, useState } from 'react';
import { DATASET_OPTIONS, metricHelp } from './constants';


export function MetricLabel({ label, className = 'td-detail-label' }) {
  const help = metricHelp(label);
  if (!help) return <div className={className}>{label}</div>;
  return (
    <div
      className={`${className} td-metric-help`}
      tabIndex={0}
      title={help}
      aria-label={`${label}: ${help}`}
      data-help={help}
    >
      <span>{label}</span>
      <span className="td-help-dot" aria-hidden="true">?</span>
    </div>
  );
}

export function DatasetSelector({ value, onChange }) {
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
export function LogBox({ lines, height = '220px' }) {
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
export function FileDropZone({ file, onFile, inputId, icon = '📂', accept = '.csv,.parquet,.pq', dropText = null }) {
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
export function MetricsGrid({ result }) {
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
            <MetricLabel label={label} />
            <div className="td-model-metric-value">{type === 'count' ? val.toLocaleString() : formatMetric(label, val)}</div>
          </div>
        ))}
      </div>

      {counts.length > 0 && (
        <div className="td-confusion-grid">
          {counts.map(([label, val]) => (
            <div key={label} className="td-confusion-row">
              <MetricLabel label={label} className="td-confusion-label" />
              <strong>{val.toLocaleString()}</strong>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function ThresholdSummary({ analysis }) {
  const rec = analysis?.recommended;
  if (!analysis?.available || !rec) return null;
  const pct = value => value != null ? `${(value * 100).toFixed(1)}%` : '—';
  const fprCap = analysis.target_fpr_range?.[1];
  return (
    <div className="td-threshold-summary">
      <div className="td-section-label">Threshold Tradeoff Summary</div>
      <div className="td-detail-note">
        Report-only recommendation optimized for Recall under a {pct(fprCap)} labelled FPR cap. It does not change the saved unsupervised model threshold.
      </div>
      <div className="td-detail-metrics">
        <div className="td-detail-metric">
          <MetricLabel label="Recommended Threshold" />
          <div className="td-detail-value">{rec.threshold?.toFixed ? rec.threshold.toFixed(4) : rec.threshold}</div>
        </div>
        <div className="td-detail-metric">
          <MetricLabel label="Recall / TPR" />
          <div className="td-detail-value" style={{ color: 'var(--success)' }}>{pct(rec.recall)}</div>
        </div>
        <div className="td-detail-metric">
          <MetricLabel label="FNR" />
          <div className="td-detail-value" style={{ color: 'var(--danger)' }}>{pct(rec.false_negative_rate)}</div>
        </div>
        <div className="td-detail-metric">
          <MetricLabel label="FPR" />
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

export function SummaryIcon({ src, alt, tone }) {
  return <img className={`td-summary-icon ${tone || ''}`} src={src} alt={alt} />;
}

// ══════════════════════════════════════════════════════════════
//  TRAINING TAB
// ══════════════════════════════════════════════════════════════
