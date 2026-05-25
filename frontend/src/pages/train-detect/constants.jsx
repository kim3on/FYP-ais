export const DATASET_OPTIONS = [
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

export const METRIC_HELP = {
  'Active Antibodies': 'Number of mature NSA/V-detectors stored after benign-only training. More detectors can improve coverage but may increase runtime.',
  'Unsupervised Benign Calibration': 'Normal pass rate on held-out benign calibration traffic. This is not attack accuracy; it checks how much benign traffic passes the unsupervised threshold.',
  'Current Dataset': 'Dataset profile currently loaded or trained for this page.',
  'Target FPR': 'Target false-positive rate used to calibrate the unsupervised threshold on benign calibration traffic only.',
  'Observed Benign FPR': 'Actual percentage of benign validation flows incorrectly flagged as anomalies during calibration.',
  'Self Intrusion Rate': 'AIS autoimmunity check: benign validation samples incorrectly flagged by the AIS mechanism. Lower is better.',
  'Normal Pass Rate': 'Percentage of benign calibration flows accepted as normal. It is 1 minus the observed benign false-positive rate.',
  'Silhouette Score': 'Unsupervised separation score using predicted normal/anomaly groups in PCA space. Useful as a rough check, but limited because anomaly detection is not pure clustering.',
  'Threshold': 'Saved unsupervised NSA self-gap distance cutoff calibrated from benign traffic only.',
  'NSA Self-Gap Threshold': 'Saved unsupervised NSA self-gap distance cutoff calibrated from benign traffic only.',
  'Fitted Self-Gap Radius': 'NSA self-gap radius derived from benign PCA geometry during training.',
  'Fitted Detector Tolerance': 'V-detector self-tolerance derived from benign PCA geometry during training.',
  'Total Flows': 'Number of flows analysed in this detection run.',
  'Anomalies': 'Number of flows flagged as anomalies by the unsupervised detector.',
  'Zero-Day Candidates': 'Anomaly alerts that do not match a known detector explanation strongly enough and are treated as unknown candidates.',
  'Anomaly Rate': 'Percentage of analysed flows flagged as anomalies by the unsupervised detector.',
  'Normal Flows': 'Number of analysed flows that were not flagged as anomalies.',
  'Recall / TPR': 'Post-run labelled verification only: percentage of labelled attacks caught by the unsupervised detector.',
  'False Neg. Rate': 'Post-run labelled verification only: percentage of labelled attacks missed. Lower is better for IDS.',
  FNR: 'Post-run labelled verification only: percentage of labelled attacks missed. Lower is better for IDS.',
  'False Pos. Rate': 'Post-run labelled verification only: percentage of labelled normal flows incorrectly alerted as attacks.',
  FPR: 'Post-run labelled verification only: percentage of labelled normal flows incorrectly alerted as attacks.',
  Precision: 'Post-run labelled verification only: percentage of predicted anomalies that were actually labelled attacks.',
  'F1 Score': 'Post-run labelled verification only: harmonic mean of precision and recall.',
  'Accuracy (secondary)': 'Post-run labelled verification only. Secondary metric because IDS datasets are usually imbalanced and high accuracy can hide missed attacks.',
  'TP - Attacks Caught': 'True positives: labelled attack flows correctly flagged as anomalies.',
  'FN - Attacks Missed': 'False negatives: labelled attack flows incorrectly passed as normal.',
  'FP - False Alarms': 'False positives: labelled normal flows incorrectly flagged as anomalies.',
  'TN - Normal Passed': 'True negatives: labelled normal flows correctly passed as normal.',
  'Recommended Threshold': 'Report-only threshold from threshold analysis. It does not change the saved unsupervised model threshold.',
};

export function metricHelp(label) {
  return METRIC_HELP[label] || METRIC_HELP[label?.replace(/\s+/g, ' ')] || '';
}
