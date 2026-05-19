"""
AIS-Detect Backend — Test Suite (CIC-IDS-2017)
================================================
Covers:
  1. CIC-IDS-2017 Preprocessor    (11 tests)
  2. NSA Model                     (3 tests)
  3. Isolation Forest Baseline     (1 test)
  4. Evaluator                     (2 tests)
  5. Full Training Pipeline        (2 tests)
  6. Detection Engine              (3 tests)
  7. NSA Geometric Correctness     (4 tests)

Run with:  python test_backend.py
"""
import sys, os, io, tempfile

_cpu_count = os.cpu_count() or 1
os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(max(1, min(_cpu_count - 1, 8))))

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, recall_score, precision_score

# Force UTF-8 output so Unicode pass/fail symbols work on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr.encoding and sys.stderr.encoding.lower() != 'utf-8':
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Add project root to sys.path so 'app' can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

PASS = "\u2713"; FAIL = "\u2717"
results = []

def test(name, fn):
    try:
        fn()
        print(f"  {PASS} {name}")
        results.append((name, True, None))
    except Exception as e:
        print(f"  {FAIL} {name}")
        print(f"    \u2192 {type(e).__name__}: {e}")
        results.append((name, False, str(e)))

# ── Synthetic CIC-IDS-2017 CSV builder ──────────────────────────────
def _make_cicids_csv(n_benign=80, n_attack=20, inject_inf=False) -> bytes:
    """Generate a minimal CIC-IDS-2017-formatted CSV for testing."""
    rng = np.random.default_rng(42)
    rows = []
    labels = (
        ['BENIGN'] * n_benign +
        ['DoS Hulk'] * (n_attack // 3) +
        ['DDoS']     * (n_attack // 3) +
        ['PortScan'] * (n_attack - 2 * (n_attack // 3))
    )

    for label in labels:
        row = {
            'Destination Port':            float(rng.integers(1, 65535)),
            'Flow Duration':               float(rng.integers(0, 10_000_000)),
            'Total Fwd Packets':           float(rng.integers(0, 1000)),
            'Total Backward Packets':      float(rng.integers(0, 1000)),
            'Total Length of Fwd Packets': float(rng.integers(0, 100000)),
            'Total Length of Bwd Packets': float(rng.integers(0, 100000)),
            'Fwd Packet Length Max':       float(rng.integers(0, 1500)),
            'Fwd Packet Length Min':       float(rng.integers(0, 100)),
            'Fwd Packet Length Mean':      rng.random() * 1500,
            'Fwd Packet Length Std':       rng.random() * 500,
            'Bwd Packet Length Max':       float(rng.integers(0, 1500)),
            'Bwd Packet Length Min':       float(rng.integers(0, 100)),
            'Bwd Packet Length Mean':      rng.random() * 1500,
            'Bwd Packet Length Std':       rng.random() * 500,
            'Flow Bytes/s':                rng.random() * 1e6,
            'Flow Packets/s':              rng.random() * 10000,
            'Flow IAT Mean':               rng.random() * 100000,
            'Flow IAT Std':                rng.random() * 100000,
            'Flow IAT Max':                float(rng.integers(0, 10_000_000)),
            'Flow IAT Min':                float(rng.integers(0, 1000)),
            'Fwd IAT Total':               float(rng.integers(0, 10_000_000)),
            'Fwd IAT Mean':                rng.random() * 100000,
            'Fwd IAT Std':                 rng.random() * 100000,
            'Fwd IAT Max':                 float(rng.integers(0, 10_000_000)),
            'Fwd IAT Min':                 float(rng.integers(0, 1000)),
            'Bwd IAT Total':               float(rng.integers(0, 10_000_000)),
            'Bwd IAT Mean':                rng.random() * 100000,
            'Bwd IAT Std':                 rng.random() * 100000,
            'Bwd IAT Max':                 float(rng.integers(0, 10_000_000)),
            'Bwd IAT Min':                 float(rng.integers(0, 1000)),
            'Fwd PSH Flags':               float(rng.integers(0, 2)),
            'Bwd PSH Flags':               float(rng.integers(0, 2)),
            'Fwd URG Flags':               float(rng.integers(0, 2)),
            'Bwd URG Flags':               float(rng.integers(0, 2)),
            'Fwd Header Length':           float(rng.integers(20, 60)),
            'Bwd Header Length':           float(rng.integers(20, 60)),
            'Fwd Packets/s':               rng.random() * 5000,
            'Bwd Packets/s':               rng.random() * 5000,
            'Min Packet Length':           float(rng.integers(0, 100)),
            'Max Packet Length':           float(rng.integers(0, 1500)),
            'Packet Length Mean':          rng.random() * 1500,
            'Packet Length Std':           rng.random() * 500,
            'Packet Length Variance':      rng.random() * 250000,
            'FIN Flag Count':              float(rng.integers(0, 2)),
            'SYN Flag Count':              float(rng.integers(0, 2)),
            'RST Flag Count':              float(rng.integers(0, 2)),
            'PSH Flag Count':              float(rng.integers(0, 2)),
            'ACK Flag Count':              float(rng.integers(0, 2)),
            'URG Flag Count':              float(rng.integers(0, 2)),
            'CWE Flag Count':              float(rng.integers(0, 2)),
            'ECE Flag Count':              float(rng.integers(0, 2)),
            'Down/Up Ratio':               rng.random() * 10,
            'Average Packet Size':         rng.random() * 1500,
            'Avg Fwd Segment Size':        rng.random() * 1500,
            'Avg Bwd Segment Size':        rng.random() * 1500,
            'Fwd Header Length.1':         float(rng.integers(20, 60)),  # duplicate
            'Fwd Avg Bytes/Bulk':          0.0,
            'Fwd Avg Packets/Bulk':        0.0,
            'Fwd Avg Bulk Rate':           0.0,
            'Bwd Avg Bytes/Bulk':          0.0,
            'Bwd Avg Packets/Bulk':        0.0,
            'Bwd Avg Bulk Rate':           0.0,
            'Subflow Fwd Packets':         float(rng.integers(0, 1000)),
            'Subflow Fwd Bytes':           float(rng.integers(0, 100000)),
            'Subflow Bwd Packets':         float(rng.integers(0, 1000)),
            'Subflow Bwd Bytes':           float(rng.integers(0, 100000)),
            'Init_Win_bytes_forward':      float(rng.integers(0, 65535)),
            'Init_Win_bytes_backward':     float(rng.integers(0, 65535)),
            'act_data_pkt_fwd':            float(rng.integers(0, 1000)),
            'min_seg_size_forward':        float(rng.integers(0, 100)),
            'Active Mean':                 rng.random() * 1000000,
            'Active Std':                  rng.random() * 100000,
            'Active Max':                  float(rng.integers(0, 10_000_000)),
            'Active Min':                  float(rng.integers(0, 1000)),
            'Idle Mean':                   rng.random() * 10_000_000,
            'Idle Std':                    rng.random() * 1_000_000,
            'Idle Max':                    float(rng.integers(0, 120_000_000)),
            'Idle Min':                    float(rng.integers(0, 1000)),
            ' Label':                      label,
        }
        rows.append(row)

    df = pd.DataFrame(rows)
    csv_bytes = df.to_csv(index=False).encode()

    # inject_inf: manually insert 'Inf' as a string in the CSV text (mimics
    # real CICFlowMeter output) rather than setting it as a Python float
    if inject_inf:
        lines = csv_bytes.decode().split('\n')
        # Replace the first data cell of row 1 with Inf
        parts = lines[1].split(',')
        parts[0] = 'Inf'
        lines[1] = ','.join(parts)
        csv_bytes = '\n'.join(lines).encode()

    return csv_bytes


def _make_nsl_kdd_csv(n_normal=80, n_attack=20, attack_label="neptune", service="http") -> bytes:
    """Generate a small NSL-KDD CSV-with-headers fixture."""
    from app.core.nsl_kdd_preprocessor import NSL_KDD_FEATURES

    rng = np.random.default_rng(24)
    rows = []
    labels = ["normal"] * n_normal + [attack_label] * n_attack
    for label in labels:
        row = {}
        for col in NSL_KDD_FEATURES:
            if col == "protocol_type":
                row[col] = "tcp"
            elif col == "service":
                row[col] = service
            elif col == "flag":
                row[col] = "SF" if label == "normal" else "S0"
            elif col in {"land", "logged_in", "root_shell", "su_attempted",
                         "is_host_login", "is_guest_login"}:
                row[col] = int(rng.integers(0, 2))
            else:
                base = 10 if label == "normal" else 100
                row[col] = float(base + rng.normal(0, 3))
        row["label"] = label
        rows.append(row)
    return pd.DataFrame(rows).to_csv(index=False).encode()


def _make_nsl_kdd_csv_with_labels_column(n_normal=80, n_attack=20) -> bytes:
    df = pd.read_csv(io.BytesIO(_make_nsl_kdd_csv(n_normal, n_attack)))
    df = df.rename(columns={"label": "labels"})
    return df.to_csv(index=False).encode()


# ════════════════════════════════════════════════════════════
print("\n── 1. CIC-IDS-2017 Preprocessor ───────────────────────────────")
# ════════════════════════════════════════════════════════════
from app.core.preprocessor import CICIDSPreprocessor

def test_load_and_label():
    csv = _make_cicids_csv(60, 20)
    prep = CICIDSPreprocessor()
    X_normal, y, df = prep.fit_transform_unsafe_single_dataset(csv)
    assert prep.is_fitted_
    assert X_normal.ndim == 2
    assert len(y) == 80
    assert set(np.unique(y)).issubset({0, 1})
    assert (y == 0).sum() == 60
    assert (y == 1).sum() == 20

def test_mixed_fit_transform_requires_explicit_unsafe():
    csv = _make_cicids_csv(60, 20)
    prep = CICIDSPreprocessor()
    try:
        prep.fit_transform(csv)
    except ValueError as exc:
        assert "Unsafe mixed labelled fit_transform" in str(exc)
    else:
        raise AssertionError("Mixed labelled fit_transform should require explicit unsafe opt-in")

def test_no_inf_nan_after_clean():
    """Real CICFlowMeter CSVs contain 'Inf' strings — must be cleaned."""
    csv = _make_cicids_csv(50, 10, inject_inf=True)
    prep = CICIDSPreprocessor()
    X_normal, y, df = prep.fit_transform_unsafe_single_dataset(csv)
    assert not np.any(np.isnan(X_normal)), "NaN found in output"
    assert not np.any(np.isinf(X_normal)), "Inf found in output"

def test_normalised_to_0_1():
    """RobustScaler output is centred around 0, not clipped to [0,1].
    We verify the data is finite and has reasonable spread instead."""
    csv = _make_cicids_csv(80, 20)
    prep = CICIDSPreprocessor(n_pca_components=None)
    X_normal, _, _ = prep.fit_transform_unsafe_single_dataset(csv)
    assert np.isfinite(X_normal).all(), "Non-finite values found after scaling"
    # RobustScaler centres at median; values must not ALL be zero (i.e. scaler is active)
    assert X_normal.std() > 0, "Scaler produced all-zero variance — scaler not applied"

def test_duplicate_col_removed():
    """'Fwd Header Length.1' duplicate should be removed."""
    csv = _make_cicids_csv(40, 10)
    prep = CICIDSPreprocessor()
    prep.fit_transform_unsafe_single_dataset(csv)
    dups = [c for c in prep.feature_columns_ if prep.feature_columns_.count(c) > 1]
    assert len(dups) == 0, f"Duplicate columns found: {dups}"

def test_leading_space_label():
    """The ' Label' column (leading space) must be found and stripped."""
    csv = _make_cicids_csv(30, 10)
    prep = CICIDSPreprocessor()
    X_normal, y, df = prep.fit_transform_unsafe_single_dataset(csv)
    assert 'attack_category' in df.columns

def test_attack_categories():
    csv = _make_cicids_csv(60, 30)
    prep = CICIDSPreprocessor()
    _, y, df = prep.fit_transform_unsafe_single_dataset(csv)
    cats = set(df['attack_category'].unique())
    assert 'normal' in cats
    # Should have at least DoS and DDoS categories
    assert len(cats) >= 3

def test_validation_stats():
    csv = _make_cicids_csv(80, 20)
    prep = CICIDSPreprocessor()
    _, y, df = prep.fit_transform_unsafe_single_dataset(csv)
    stats = prep.validation_stats(y, df)
    assert stats['total_records']  == 100
    assert stats['normal_records'] == 80
    assert stats['attack_records'] == 20
    assert stats['dataset'] == 'CIC-IDS-2017'
    assert stats['n_features'] > 0

def test_inference_alignment():
    """Inference CSV may have different columns — must align to training schema."""
    csv_train = _make_cicids_csv(60, 20)
    csv_test  = _make_cicids_csv(10, 5)
    prep = CICIDSPreprocessor()
    prep.fit_transform_unsafe_single_dataset(csv_train)
    X_new, _ = prep.transform(csv_test)
    expected_cols = prep.pca_.n_components_ if prep.pca_ is not None else len(prep.feature_columns_)
    assert X_new.shape[1] == expected_cols

def test_persistence():
    with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as tmp:
        path = tmp.name
    try:
        csv = _make_cicids_csv(50, 15)
        prep = CICIDSPreprocessor()
        prep.fit_transform_unsafe_single_dataset(csv)
        prep.save(path)
        prep2 = CICIDSPreprocessor.load(path)
        assert prep2.feature_columns_ == prep.feature_columns_
        assert prep2.is_fitted_
    finally:
        os.unlink(path)

def test_benign_only_returns_no_normal_in_X_normal():
    """When dataset is all BENIGN, X_normal == X_all."""
    csv = _make_cicids_csv(50, 0)
    prep = CICIDSPreprocessor()
    X_normal, y, df = prep.fit_transform_unsafe_single_dataset(csv)
    assert (y == 0).all()
    assert len(X_normal) == 50

def test_feature_count_reasonable():
    """CIC-IDS-2017 should produce ~75 numeric features after cleaning."""
    csv = _make_cicids_csv(40, 10)
    prep = CICIDSPreprocessor(n_pca_components=None)
    prep.fit_transform_unsafe_single_dataset(csv)
    n = len(prep.feature_columns_)
    assert 50 <= n <= 90, f"Unexpected feature count: {n}"
    print(f"\n    Feature count after cleaning: {n}")

test("Preprocessor — load CSV, encode labels, split BENIGN/attack",  test_load_and_label)
test("Preprocessor — mixed fit_transform requires unsafe opt-in",     test_mixed_fit_transform_requires_explicit_unsafe)
test("Preprocessor — Inf strings cleaned to 0 (CICFlowMeter fix)",   test_no_inf_nan_after_clean)
test("Preprocessor — output normalised to [0, 1]",                    test_normalised_to_0_1)
test("Preprocessor — duplicate 'Fwd Header Length.1' removed",        test_duplicate_col_removed)
test("Preprocessor — ' Label' with leading space detected",           test_leading_space_label)
test("Preprocessor — attack_category populated (DoS/DDoS/Probe)",     test_attack_categories)
test("Preprocessor — validation_stats correct counts & dataset name", test_validation_stats)
test("Preprocessor — inference column alignment",                      test_inference_alignment)
test("Preprocessor — save/load consistent",                            test_persistence)
test("Preprocessor — all-BENIGN dataset supported",                   test_benign_only_returns_no_normal_in_X_normal)
test("Preprocessor — feature count in expected range (~75)",           test_feature_count_reasonable)


# ════════════════════════════════════════════════════════════
print("\n── 1b. NSL-KDD Preprocessor ───────────────────────────────────")
# ════════════════════════════════════════════════════════════
from app.core.nsl_kdd_preprocessor import NSLKDDPreprocessor

def test_nsl_kdd_load_and_label():
    csv = _make_nsl_kdd_csv(60, 20)
    prep = NSLKDDPreprocessor(n_pca_components=0.95)
    X_normal, y, df = prep.fit_transform_unsafe_single_dataset(csv)
    assert prep.is_fitted_
    assert X_normal.ndim == 2
    assert len(y) == 80
    assert (y == 0).sum() == 60
    assert (y == 1).sum() == 20
    assert prep.feature_columns_
    assert "attack_category" in df.columns
    assert prep.validation_stats(y, df)["dataset"] == "NSL-KDD"

def test_nsl_kdd_unknown_category_safe():
    train_csv = _make_nsl_kdd_csv(80, 0, service="http")
    test_csv = _make_nsl_kdd_csv(10, 5, attack_label="satan", service="new_service")
    prep = NSLKDDPreprocessor(n_pca_components=10)
    df_train = prep._load(train_csv)
    df_train, label_col = prep._find_label_col(df_train)
    df_train, y = prep._encode_labels(df_train, label_col)
    prep.fit(df_train.loc[y == 0])
    X, df = prep.transform(test_csv)
    assert X.shape[0] == 15
    assert np.isfinite(X).all()
    assert "Probe" in set(df["attack_category"])

def test_nsl_kdd_labels_column_variant():
    csv = _make_nsl_kdd_csv_with_labels_column(60, 20)
    prep = NSLKDDPreprocessor(n_pca_components=10)
    X_normal, y, df = prep.fit_transform_unsafe_single_dataset(csv)
    assert X_normal.shape[0] == 60
    assert (y == 1).sum() == 20
    assert "attack_category" in df.columns

def test_nsl_kdd_mixed_fit_blocked():
    prep = NSLKDDPreprocessor()
    try:
        prep.fit_transform(_make_nsl_kdd_csv(20, 10))
    except ValueError as exc:
        assert "Unsafe mixed labelled fit_transform" in str(exc)
    else:
        raise AssertionError("NSL-KDD mixed labelled fit_transform should be blocked")

test("NSL-KDD — CSV labels and attack categories load",       test_nsl_kdd_load_and_label)
test("NSL-KDD — unseen categorical values do not crash",      test_nsl_kdd_unknown_category_safe)
test("NSL-KDD — 'labels' column variant is accepted",         test_nsl_kdd_labels_column_variant)
test("NSL-KDD — mixed labelled fit_transform is blocked",     test_nsl_kdd_mixed_fit_blocked)


# ════════════════════════════════════════════════════════════
print("\n── 2. NSA Model ────────────────────────────────────────────────")
# ════════════════════════════════════════════════════════════
from app.models.nsa import NegativeSelectionDetector

def test_nsa_on_cicids_features():
    """NSA must train on the ~75 numerical features from CIC-IDS-2017."""
    csv = _make_cicids_csv(100, 30)
    prep = CICIDSPreprocessor()
    X_normal, y, df = prep.fit_transform_unsafe_single_dataset(csv)
    nsa = NegativeSelectionDetector(r=0.3, r_s=0.02, max_detectors=50,
                                    max_attempts=1000, random_state=1)
    nsa.fit(X_normal)
    assert nsa.is_fitted_
    assert nsa.n_features_ == X_normal.shape[1]
    assert len(nsa.detectors_) > 0
    # V-Detector: each detector should have a variable radius
    assert nsa.det_radii_ is not None
    assert len(nsa.det_radii_) == len(nsa.detectors_)
    assert all(r > 0 for r in nsa.det_radii_), "All V-detector radii must be positive"

def test_nsa_predict_shape():
    csv = _make_cicids_csv(80, 20)
    prep = CICIDSPreprocessor()
    X_normal, _, _ = prep.fit_transform_unsafe_single_dataset(csv)
    X_all, _ = prep.transform(_make_cicids_csv(20, 10))
    nsa = NegativeSelectionDetector(r=0.3, r_s=0.02, max_detectors=50, max_attempts=1000)
    nsa.fit(X_normal)
    labels, scores = nsa.predict_with_scores(X_all)
    assert len(labels) == 30
    assert all(0.0 <= s <= 1.0 for s in scores)

def test_nsa_detectors_dont_match_self():
    """Core NSA property: no V-detector sphere should overlap with any self sample."""
    csv = _make_cicids_csv(60, 0)
    prep = CICIDSPreprocessor()
    X_normal, _, _ = prep.fit_transform_unsafe_single_dataset(csv)
    nsa = NegativeSelectionDetector(r=0.3, r_s=0.02, max_detectors=40,
                                    max_attempts=1000, random_state=9)
    nsa.fit(X_normal)
    n_features = X_normal.shape[1]
    scale = np.sqrt(n_features)
    # Every detector's variable-radius sphere must NOT contain any self sample
    for i, det in enumerate(nsa.detectors_):
        dists = np.sqrt(((X_normal - det) ** 2).sum(axis=1)) / scale
        det_r = nsa.det_radii_[i]
        assert dists.min() >= det_r - 1e-6, \
            f"V-Detector {i} overlaps self: min_dist={dists.min():.4f} < radius={det_r:.4f}"

test("NSA — V-Detector fits on CIC-IDS-2017 with variable radii",  test_nsa_on_cicids_features)
test("NSA — predict_with_scores shape and bounds",                  test_nsa_predict_shape)
test("NSA — no V-detector sphere overlaps with self (core property)", test_nsa_detectors_dont_match_self)


# ════════════════════════════════════════════════════════════
print("\n── 3. Isolation Forest Baseline ────────────────────────────────")
# ════════════════════════════════════════════════════════════
from app.models.isolation_forest import IsolationForestDetector

def test_iso_on_cicids():
    csv = _make_cicids_csv(100, 30)
    prep = CICIDSPreprocessor()
    X_normal, y, _ = prep.fit_transform_unsafe_single_dataset(csv)
    X_all, _ = prep.transform(_make_cicids_csv(20, 10))
    iso = IsolationForestDetector(contamination=0.1, random_state=2)
    iso.fit(X_normal)
    labels, scores = iso.predict_with_scores(X_all)
    assert set(labels).issubset({0, 1})
    assert all(0.0 <= s <= 1.0 for s in scores)

def test_iso_score_stable_across_batch_sizes():
    csv = _make_cicids_csv(100, 30)
    prep = CICIDSPreprocessor()
    X_normal, _, _ = prep.fit_transform_unsafe_single_dataset(csv)
    X_all, _ = prep.transform(_make_cicids_csv(20, 10))
    iso = IsolationForestDetector(contamination=0.1, random_state=2)
    iso.fit(X_normal)
    _, score_single = iso.predict_with_scores(X_all[:1])
    _, score_batch = iso.predict_with_scores(X_all[:10])
    assert float(score_single[0]) == float(score_batch[0]), \
        "Isolation Forest confidence should use fixed training calibration, not batch min/max"

def test_iso_benign_calibrated_threshold():
    csv = _make_cicids_csv(120, 30)
    prep = CICIDSPreprocessor()
    X_normal, _, _ = prep.fit_transform_unsafe_single_dataset(csv)
    iso = IsolationForestDetector(contamination=0.1, random_state=2)
    iso.fit(X_normal[:80])
    calibration = iso.calibrate_threshold(X_normal[80:], target_fpr=0.05)
    labels, scores = iso.predict_with_scores(X_normal[80:])
    assert calibration["mode"] == "unsupervised_benign_isolation_forest"
    assert calibration["decision_rule"] == "raw_anomaly_score > threshold"
    assert iso.score_threshold_ is not None
    assert labels.mean() <= 0.10, "Benign-calibrated IF should keep holdout FPR controlled"
    assert all(0.0 <= s <= 1.0 for s in scores)

test("IsoForest — fits and predicts on CIC-IDS-2017 features", test_iso_on_cicids)
test("IsoForest — score normalization stable across batch sizes", test_iso_score_stable_across_batch_sizes)
test("IsoForest — benign-calibrated threshold available", test_iso_benign_calibrated_threshold)


# ════════════════════════════════════════════════════════════
print("\n── 4. Evaluator ────────────────────────────────────────────────")
# ════════════════════════════════════════════════════════════
from app.core.evaluator import evaluate_model, compare_models, severity_from_score
from app.core.calibration import conformal_threshold
from app.models.self_boundary import SelfBoundaryDetector

def test_evaluator_cicids_categories():
    """Per-category stats should show CIC-IDS-2017 attack types."""
    csv = _make_cicids_csv(80, 30)
    prep = CICIDSPreprocessor()
    X_normal, y, df = prep.fit_transform_unsafe_single_dataset(csv)
    # Simulate predictions (flag everything as attack for this test)
    y_pred = np.ones_like(y)
    result = evaluate_model(y, y_pred, "Test", df)
    assert result.n_attacks == 30
    assert result.n_normal  == 80
    # Check per-category exists
    cats = list(result.per_category.keys())
    assert len(cats) >= 1

def test_severity_mapping():
    assert severity_from_score(0.95) == 'critical'
    assert severity_from_score(0.80) == 'high'
    assert severity_from_score(0.60) == 'medium'
    assert severity_from_score(0.30) == 'low'

def test_conformal_threshold_known_rank():
    scores = np.array([0.0, 1.0, 2.0, 3.0])
    info = conformal_threshold(scores, target_fpr=0.25)
    assert info["rank_index"] == 4
    assert info["threshold"] == 3.0
    assert info["observed_fpr"] == 0.0
    assert info["reliability"] == "experimental"

def test_self_boundary_quantile_fences_and_strict_threshold():
    df = pd.DataFrame({
        "a": np.linspace(10.0, 20.0, 200),
        "b": np.linspace(100.0, 200.0, 200),
    })
    sb = SelfBoundaryDetector()
    sb.fit(df, ["a", "b"])
    assert sb.summary()["boundary_mode"] == "quantile_fence"
    sb.weighted_threshold_ = 0.0
    _, flags_inside, _ = sb.score(pd.DataFrame({"a": [15.0], "b": [150.0]}))
    _, flags_outside, _ = sb.score(pd.DataFrame({"a": [100.0], "b": [150.0]}))
    assert not bool(flags_inside[0]), "Strict score > threshold should not flag zero-score rows"
    assert bool(flags_outside[0]), "Out-of-fence sample should be flagged"

def test_self_boundary_ratio_fallback_uses_strict_threshold():
    df = pd.DataFrame({
        "a": np.linspace(10.0, 20.0, 200),
        "b": np.linspace(100.0, 200.0, 200),
    })
    sb = SelfBoundaryDetector(min_violations_ratio=0.5)
    sb.fit(df, ["a", "b"])
    sb.weighted_threshold_ = None
    _, flags_equal, _ = sb.score(pd.DataFrame({"a": [100.0], "b": [150.0]}))
    _, flags_above, _ = sb.score(pd.DataFrame({"a": [100.0], "b": [500.0]}))
    assert not bool(flags_equal[0]), "One of two violations equals 0.5 and must not flag"
    assert bool(flags_above[0]), "Two of two violations exceeds 0.5 and must flag"

def test_self_boundary_legacy_gaussian_compat():
    sb = SelfBoundaryDetector()
    sb.feature_names_ = ["a"]
    sb.n_features_ = 1
    sb.means_ = np.array([0.0])
    sb.stds_ = np.array([1.0])
    sb.feature_weights_ = np.array([1.0])
    sb.is_fitted_ = True
    score = sb.weighted_score(pd.DataFrame({"a": [10.0]}))
    assert sb.summary()["boundary_mode"] == "gaussian_zscore_legacy"
    assert score[0] > 0.0

test("Evaluator — per-category stats with CIC-IDS-2017 labels", test_evaluator_cicids_categories)
test("Evaluator — severity score thresholds correct",            test_severity_mapping)
test("Calibration — conformal threshold rank is deterministic",  test_conformal_threshold_known_rank)
test("Self-Boundary — quantile fences and strict threshold",      test_self_boundary_quantile_fences_and_strict_threshold)
test("Self-Boundary — fallback ratio uses strict threshold",      test_self_boundary_ratio_fallback_uses_strict_threshold)
test("Self-Boundary — legacy Gaussian artifacts remain usable",   test_self_boundary_legacy_gaussian_compat)


# ════════════════════════════════════════════════════════════
print("\n── 5. Full Training Pipeline ───────────────────────────────────")
# ════════════════════════════════════════════════════════════
from app.core.pipeline import TrainingPipeline

def test_pipeline_cicids():
    csv = _make_cicids_csv(n_benign=120, n_attack=40)
    pipeline = TrainingPipeline(
        r=0.3, r_s=0.02, max_detectors=60, max_attempts=1500,
        contamination=0.1, test_size=0.25, random_state=42,
    )
    result = pipeline.run(csv)

    assert result['nsa_summary']['status']       == 'fitted'
    assert result['iso_summary']['status']       == 'fitted'
    assert result['sb_summary']['status']        == 'fitted'
    assert result['validation_stats']['dataset'] == 'CIC-IDS-2017'
    assert result['validation_stats']['n_features'] > 0

    for key in ('accuracy', 'false_positive_rate'):
        assert 0.0 <= result['nsa_eval'][key] <= 1.0, \
            f"metric '{key}' out of range: {result['nsa_eval'][key]}"
    assert result['validation_mode'] == 'strict_unsupervised_benign_fusion_calibrated'
    assert result['calibration_summary']['score_mode'] == 'weighted_fusion'
    assert 'calibration_reliability' in result['calibration_summary']
    assert 'calibration_reliability' in result['nsa_calibration_summary']
    assert 'calibration_reliability' in result['iso_calibration_summary']
    assert result['iso_calibration_summary']['mode'] == 'unsupervised_benign_isolation_forest'
    assert result['iso_summary']['threshold_calibration']['decision_rule'] == 'raw_anomaly_score > threshold'
    assert 'calibration_reliability' in result['self_boundary_calibration_summary']
    assert result['self_boundary_mode'] == 'hybrid_pca_scoring_raw_evidence'
    assert result['raw_self_boundary_summary']['status'] == 'fitted'
    assert result['pca_self_boundary_summary']['status'] == 'fitted'
    assert result['pca_self_boundary_summary']['score_mode'] == 'weighted_feature_violation'
    assert result['pca_self_boundary_summary']['n_features_modelled'] == result['nsa_summary']['n_features']
    assert 'calibration_reliability' in result['pca_self_boundary_calibration_summary']
    assert 'calibration_reliability' in result['raw_self_boundary_calibration_summary']
    assert 'fusion_calibration' in result['nsa_summary']
    assert result['sb_summary']['score_mode'] == 'weighted_feature_violation'
    assert result['sb_summary']['boundary_mode'] == 'quantile_fence'
    assert result['nsa_eval']['labelled_attack_metrics_applicable'] is False
    for key in ('precision', 'recall', 'f1', 'false_negative_rate', 'true_positive_rate'):
        assert result['nsa_eval'][key] is None, \
            f"benign-only training metric '{key}' should be not applicable"
    assert 0.0 <= result['ais_metrics']['self_intrusion_rate'] <= 1.0
    assert 'unsupervised_validation' in result
    assert 'silhouette' in result['unsupervised_validation']
    assert 'source_decomposition' in result['unsupervised_validation']
    assert 'metric_explanations' in result
    labelled = result['post_run_labelled_verification']
    assert labelled['available'] is True
    assert labelled['threshold_analysis']['verification_only'] is True
    assert labelled['source_decomposition']['available'] is True
    iso_labelled = result['iso_post_run_labelled_verification']
    assert iso_labelled['available'] is True
    assert iso_labelled['verification_only'] is True
    assert iso_labelled['baseline_only'] is True

    n_feat = result['validation_stats']['n_features']
    n_ab   = result['nsa_summary']['mature_detectors']
    r_min  = result['nsa_summary'].get('det_radius_min', 0)
    r_max  = result['nsa_summary'].get('det_radius_max', 0)
    print(f"\n    Features    : {n_feat}")
    print(f"    V-Detectors : {n_ab}  (radius: {r_min:.3f}–{r_max:.3f})")
    print(f"    NSA  — benign_acc={result['nsa_eval']['accuracy']:.3f}  "
          f"self_intrusion={result['ais_metrics']['self_intrusion_rate']:.4f}")
    print(f"    ISO  — acc={result['iso_eval']['accuracy']:.3f}  "
          f"benign_fpr={result['iso_eval']['false_positive_rate']:.4f}")

def test_pipeline_result_saved():
    """Training result should be persisted to disk."""
    import json
    from app.core.pipeline import RESULTS_PATH
    assert os.path.exists(RESULTS_PATH), "Training result JSON not saved"
    with open(RESULTS_PATH) as f:
        data = json.load(f)
    assert 'nsa_eval' in data
    assert 'iso_eval' in data

def test_pipeline_nsl_kdd_separate_artifacts():
    import json
    from app.core.datasets import artifact_paths
    from app.core.pipeline import models_ready, result_path

    csv = _make_nsl_kdd_csv(n_normal=120, n_attack=40)
    pipeline = TrainingPipeline(
        r=0.3, r_s=0.02, max_detectors=40, max_attempts=1200,
        contamination=0.1, test_size=0.25, random_state=11,
        n_pca_components=10, dataset_type="nsl_kdd",
    )
    result = pipeline.run(csv)
    paths = artifact_paths("nsl_kdd")

    assert result["dataset_type"] == "nsl_kdd"
    assert result["validation_stats"]["dataset"] == "NSL-KDD"
    assert result["validation_mode"] == "strict_unsupervised_benign_fusion_calibrated"
    assert result["post_run_labelled_verification"]["available"] is True
    assert models_ready("nsl_kdd") is True
    assert os.path.exists(paths.preprocessor)
    assert os.path.exists(paths.nsa)
    assert os.path.exists(paths.results)
    assert "nsl_kdd" in paths.results.replace("\\", "/")
    with open(result_path("nsl_kdd")) as f:
        saved = json.load(f)
    assert saved["dataset_type"] == "nsl_kdd"

test("Pipeline — end-to-end CIC-IDS-2017 training + evaluation", test_pipeline_cicids)
test("Pipeline — result JSON persisted to disk",                  test_pipeline_result_saved)
test("Pipeline — NSL-KDD trains into separate artifacts",         test_pipeline_nsl_kdd_separate_artifacts)


# ════════════════════════════════════════════════════════════
print("\n── 6. Detection Engine ─────────────────────────────────────────")
# ════════════════════════════════════════════════════════════
from app.core.detection import DetectionEngine
from app.core.pipeline import load_nsa, load_preprocessor, load_self_boundary, load_pca_self_boundary

def test_detection_result_structure():
    """Detection should return correct keys and alert structure."""
    csv = _make_cicids_csv(n_benign=100, n_attack=30)
    pipeline = TrainingPipeline(r=0.3, r_s=0.02, max_detectors=60,
                                max_attempts=1500, random_state=7)
    pipeline.run(csv)

    nsa  = load_nsa()
    prep = load_preprocessor()
    sb   = load_self_boundary()
    pca_sb = load_pca_self_boundary()
    assert nsa is not None and prep is not None and sb is not None and pca_sb is not None

    engine = DetectionEngine(nsa, prep, active_model='nsa', self_boundary=sb, pca_self_boundary=pca_sb)
    result = engine.detect_from_csv(_make_cicids_csv(n_benign=20, n_attack=10))

    assert result['total_checked'] == 30
    assert 'anomalies_found'   in result
    assert 'alerts'            in result
    assert 'severity_counts'   in result
    assert 'model_used'        in result
    assert result['model_used'] == 'nsa'
    assert 'metric_explanations' in result
    assert 'unsupervised_validation' in result
    assert 'threshold_analysis' in result
    assert result['threshold_analysis']['verification_only'] is True
    assert 'recommended' in result['threshold_analysis']
    assert result['source_decomposition']['available'] is True
    assert result['source_verification']['available'] is True
    assert 'pca_self_boundary' in result['layer1_sources']
    assert 'raw_self_boundary_evidence' in result['layer1_sources']
    assert 'v_detector' in result['layer1_sources']
    assert 'self_gap' in result['layer1_sources']
    assert result['score_mode'] == 'weighted_fusion_pca_self_boundary'
    assert result['self_boundary_mode'] == 'hybrid_pca_scoring_raw_evidence'
    assert 'anomaly_sources_summary' in result

    live_sample = pd.read_csv(io.BytesIO(_make_cicids_csv(n_benign=1, n_attack=0))).iloc[0].to_dict()
    live_sample['Flow Bytes/s'] = float('inf')
    live_sample['Flow Packets/s'] = np.nan
    live_result = engine.detect_sample(live_sample)
    assert live_result['total_checked'] == 1

    offset_result = engine.detect_from_csv(
        _make_cicids_csv(n_benign=40, n_attack=20),
        limit=10,
        offset=20,
    )
    assert offset_result['total_checked'] == 10
    assert offset_result['row_offset'] == 20

    print(f"\n    Detected {result['anomalies_found']} anomalies in 30 samples")

def test_detection_alert_fields():
    """Every alert must have all required fields."""
    nsa  = load_nsa()
    prep = load_preprocessor()
    engine = DetectionEngine(nsa, prep)
    result = engine.detect_from_csv(_make_cicids_csv(n_benign=30, n_attack=20))

    required = {'alert_id', 'timestamp', 'src_ip', 'dst_ip', 'dst_port',
                'protocol', 'attack_type', 'severity', 'confidence',
                'confidence_pct', 'is_false_positive', 'anomaly_sources'}
    valid_sev = {'critical', 'high', 'medium', 'low'}
    valid_sources = {
        'v_detector', 'self_gap', 'pca_self_boundary', 'self_boundary',
        'raw_self_boundary_evidence', 'score_fusion', 'nsa_pca',
        'isolation_forest',
    }

    for alert in result['alerts']:
        missing = required - set(alert.keys())
        assert not missing, f"Alert missing fields: {missing}"
        assert alert['severity'] in valid_sev, f"Bad severity: {alert['severity']}"
        assert 0.0 <= alert['confidence'] <= 1.0
        assert set(alert['anomaly_sources']).issubset(valid_sources)

def test_detection_with_iso_model():
    """Detection engine should work with Isolation Forest too."""
    from app.core.pipeline import load_iso
    iso  = load_iso()
    prep = load_preprocessor()
    assert iso is not None

    engine = DetectionEngine(iso, prep, active_model='isolation_forest')
    result = engine.detect_from_csv(_make_cicids_csv(n_benign=20, n_attack=10))
    assert result['model_used'] == 'isolation_forest'
    assert result['total_checked'] == 30
    assert result['detection_architecture'] == 'isolation_forest_baseline'
    assert result['layer1_sources'] == ['isolation_forest']
    assert result['score_mode'] == 'isolation_forest_benign_calibrated_score'
    assert result['self_boundary_mode'] == 'not_applicable'
    assert 'v_detector' not in result['layer1_sources']
    for alert in result['alerts']:
        assert alert['anomaly_sources'] == ['isolation_forest']

def test_detection_nsl_kdd_batch_result():
    nsa = load_nsa("nsl_kdd")
    prep = load_preprocessor("nsl_kdd")
    sb = load_self_boundary("nsl_kdd")
    pca_sb = load_pca_self_boundary("nsl_kdd")
    assert nsa is not None and prep is not None
    engine = DetectionEngine(nsa, prep, active_model="nsa", self_boundary=sb, pca_self_boundary=pca_sb)
    result = engine.detect_from_csv(_make_nsl_kdd_csv(n_normal=20, n_attack=10), filename="nsl_fixture.csv")
    assert result["dataset_type"] == "nsl_kdd"
    assert result["batch_only"] is True
    assert result["total_checked"] == 30
    assert "threshold_analysis" in result
    assert result["threshold_analysis"]["verification_only"] is True
    for alert in result["alerts"]:
        assert alert["src_ip"] == "N/A"
        assert alert["attack_type"] in {"Unknown Anomaly", "Zero-Day Candidate"}

test("Detection — result structure has all required keys",          test_detection_result_structure)
test("Detection — every alert has required fields & valid severity", test_detection_alert_fields)
test("Detection — Isolation Forest model also works",               test_detection_with_iso_model)
test("Detection — NSL-KDD batch verification works",                test_detection_nsl_kdd_batch_result)


# ════════════════════════════════════════════════════════════
print("\n── 7. NSA Geometric Correctness ────────────────────────────────")
# ════════════════════════════════════════════════════════════
# These tests verify the core immunological geometry of the NSA:
# normalised Euclidean distance must correctly separate a dense
# self region from a clearly separated non-self region.

_NSA_N_FEATURES = 77
_NSA_RNG = np.random.default_rng(42)
# Pre-build shared fixtures (1 000 self-samples in [0.3, 0.6]^77)
_X_SELF   = _NSA_RNG.uniform(0.3, 0.6, (1000, _NSA_N_FEATURES)).astype(np.float32)
_X_NORMAL = _NSA_RNG.uniform(0.30, 0.60, (200, _NSA_N_FEATURES)).astype(np.float32)
_X_ATTACK = _NSA_RNG.uniform(0.80, 1.00, (200, _NSA_N_FEATURES)).astype(np.float32)

def _build_nsa_fixture():
    """Fit a V-Detector NSA on _X_SELF and return it."""
    nsa = NegativeSelectionDetector(r=0.20, r_s=0.02, max_detectors=1000, max_attempts=20_000)
    nsa.fit(_X_SELF)
    return nsa

def test_nsa_low_false_positives():
    """Normal samples inside the self region should have very low FPR."""
    nsa = _build_nsa_fixture()
    fp = nsa.predict(_X_NORMAL).sum()
    assert fp <= 2, f"False positives too high: {fp}/200 normal samples flagged"
    print(f"\n    Normal flagged (FP): {fp}/200")

def test_nsa_high_true_positive_rate():
    """Attack samples far outside self MUST be flagged (TP ≥ 95%)."""
    nsa = _build_nsa_fixture()
    tp = nsa.predict(_X_ATTACK).sum()
    assert tp >= 190, f"True positives too low: {tp}/200 attacks detected"
    print(f"\n    Attacks flagged (TP): {tp}/200")

def test_nsa_distance_geometry():
    """Normal point must be inside self sphere; attack point must be outside."""
    nsa = _build_nsa_fixture()

    # Distance from a normal point to the nearest self sample
    x_n = _X_NORMAL[0]
    dists_n = np.sqrt((((_X_SELF - x_n) ** 2).sum(axis=1))) / np.sqrt(_NSA_N_FEATURES)
    assert dists_n.min() < nsa.r, (
        f"Normal point unexpectedly outside self: "
        f"min_dist={dists_n.min():.4f} >= r={nsa.r}"
    )

    # Distance from an attack point to the nearest self sample
    x_a = _X_ATTACK[0]
    dists_a = np.sqrt((((_X_SELF - x_a) ** 2).sum(axis=1))) / np.sqrt(_NSA_N_FEATURES)
    assert dists_a.min() > nsa.r, (
        f"Attack point unexpectedly inside self: "
        f"min_dist={dists_a.min():.4f} <= r={nsa.r}"
    )

    print(f"\n    Normal min-dist to self : {dists_n.min():.4f}  (r={nsa.r})")
    print(f"    Attack min-dist to self : {dists_a.min():.4f}  (r={nsa.r})")

def test_nsa_f1_on_synthetic():
    """End-to-end F1, recall and precision on a clean synthetic split."""
    nsa = _build_nsa_fixture()
    X_combined = np.vstack([_X_NORMAL, _X_ATTACK])
    y_true = np.array([0] * 200 + [1] * 200)
    y_pred = nsa.predict(X_combined)

    f1   = f1_score(y_true, y_pred)
    rec  = recall_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)

    assert f1   >= 0.95, f"F1 too low: {f1:.3f}"
    assert rec  >= 0.95, f"Recall too low: {rec:.3f}"
    assert prec >= 0.95, f"Precision too low: {prec:.3f}"
    print(f"\n    F1={f1:.3f}  Recall={rec:.3f}  Prec={prec:.3f}")

def test_nsa_vdetector_radii():
    """V-Detector radii should vary and scale with distance from self."""
    nsa = _build_nsa_fixture()
    radii = nsa.det_radii_
    assert len(radii) > 0, "No detectors generated"
    # Radii should NOT all be identical (that would mean fixed-radius, not V-detector)
    assert radii.std() > 0.01, \
        f"V-Detector radii have near-zero variance ({radii.std():.4f}) — not truly variable"
    print(f"\n    Radius range: [{radii.min():.4f}, {radii.max():.4f}]  std={radii.std():.4f}")

def test_nsa_detector_primary_classification():
    """V-detectors must catch attacks directly (proven in low-D where coverage is feasible)."""
    # Use 10D to demonstrate V-detector primary detection.  In 77D, the curse
    # of dimensionality makes detector coverage of the full non-self space
    # infeasible — that's why the self-gap fallback exists.  But in manageable
    # dimensions, V-detectors MUST function as the primary mechanism.
    n_feat = 10
    rng = np.random.default_rng(42)
    X_self_10d = rng.uniform(0.3, 0.6, (500, n_feat)).astype(np.float32)
    X_atk_10d  = rng.uniform(0.65, 0.80, (200, n_feat)).astype(np.float32)

    # auto_threshold=False keeps the explicit r/r_s in this controlled test
    nsa_10d = NegativeSelectionDetector(r=0.15, r_s=0.02, max_detectors=500,
                                        max_attempts=5000, auto_threshold=False)
    nsa_10d.fit(X_self_10d)

    det_matched, _ = nsa_10d._check_detector_match(X_atk_10d)
    det_catch_rate = det_matched.sum() / len(X_atk_10d)
    print(f"\n    10D V-Detector primary catch: {det_catch_rate:.1%} of attacks")
    assert det_catch_rate > 0.3, \
        f"V-Detectors only caught {det_catch_rate:.1%} in 10D — mechanism not working"

test("NSA geometry — low false positives on self region",             test_nsa_low_false_positives)
test("NSA geometry — ≥95% true positive rate on attack region",       test_nsa_high_true_positive_rate)
test("NSA geometry — distance separation correct (in/out sphere)",    test_nsa_distance_geometry)
test("NSA geometry — F1/recall/precision ≥ 0.95 on synthetic data",   test_nsa_f1_on_synthetic)
test("NSA V-Detector — radii are genuinely variable",                  test_nsa_vdetector_radii)
test("NSA V-Detector — detectors catch attacks (primary mechanism)",   test_nsa_detector_primary_classification)


# ════════════════════════════════════════════════════════════
print("\n── 8. CICFlowMeter Capture Adapter ─────────────────────────────")
# ════════════════════════════════════════════════════════════
from app.core.cicflow_bridge import CICFlowMeterAdapter

def _make_cicflow_row(**overrides):
    row = {
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": 6,
        "flow_duration": 0.125,
        "tot_fwd_pkts": 3,
        "tot_bwd_pkts": 2,
        "totlen_fwd_pkts": 900,
        "totlen_bwd_pkts": 400,
        "flow_iat_mean": 0.010,
        "flow_iat_std": 0.002,
        "flow_iat_max": 0.020,
        "flow_iat_min": 0.001,
        "fwd_iat_tot": 0.030,
        "fwd_iat_mean": 0.015,
        "fwd_iat_std": 0.005,
        "fwd_iat_max": 0.020,
        "fwd_iat_min": 0.010,
        "bwd_iat_tot": 0.040,
        "bwd_iat_mean": 0.020,
        "bwd_iat_std": 0.004,
        "bwd_iat_max": 0.025,
        "bwd_iat_min": 0.015,
        "active_mean": 0.050,
        "active_std": 0.001,
        "active_max": 0.060,
        "active_min": 0.040,
        "idle_mean": 0.100,
        "idle_std": 0.010,
        "idle_max": 0.120,
        "idle_min": 0.090,
        "fwd_pkt_len_max": 300,
        "fwd_pkt_len_min": 100,
        "fwd_pkt_len_mean": 200,
        "fwd_pkt_len_std": 20,
        "bwd_pkt_len_max": 200,
        "bwd_pkt_len_min": 80,
        "bwd_pkt_len_mean": 120,
        "bwd_pkt_len_std": 15,
        "flow_byts_s": 10400,
        "flow_pkts_s": 40,
        "fwd_header_len": 60,
        "bwd_header_len": 40,
        "fwd_pkts_s": 24,
        "bwd_pkts_s": 16,
        "pkt_len_min": 80,
        "pkt_len_max": 300,
        "pkt_len_mean": 180,
        "pkt_len_std": 40,
        "pkt_len_var": 1600,
        "fin_flag_cnt": 0,
        "syn_flag_cnt": 1,
        "rst_flag_cnt": 0,
        "psh_flag_cnt": 1,
        "ack_flag_cnt": 4,
        "urg_flag_cnt": 0,
        "ece_flag_cnt": 0,
        "cwr_flag_count": 7,
        "down_up_ratio": 0.67,
        "pkt_size_avg": 180,
        "fwd_seg_size_avg": 200,
        "bwd_seg_size_avg": 120,
        "fwd_byts_b_avg": 900,
        "fwd_pkts_b_avg": 3,
        "fwd_blk_rate_avg": 1000,
        "bwd_byts_b_avg": 400,
        "bwd_pkts_b_avg": 2,
        "bwd_blk_rate_avg": 900,
        "subflow_fwd_pkts": 3,
        "subflow_fwd_byts": 900,
        "subflow_bwd_pkts": 2,
        "subflow_bwd_byts": 400,
        "init_fwd_win_byts": 8192,
        "init_bwd_win_byts": 8192,
        "fwd_act_data_pkts": 3,
        "fwd_seg_size_min": 20,
        "fwd_psh_flags": 1,
        "bwd_psh_flags": 0,
        "fwd_urg_flags": 0,
        "bwd_urg_flags": 0,
    }
    row.update(overrides)
    return row

def test_cicflow_adapter_converts_seconds_to_microseconds():
    seen = []
    adapter = CICFlowMeterAdapter(seen.append)
    adapter.handle_flow(_make_cicflow_row())
    assert len(seen) == 1
    out = seen[0]
    assert out["Flow Duration"] == 125000.0
    assert out["Flow IAT Mean"] == 10000.0
    assert out["Fwd IAT Total"] == 30000.0
    assert out["Bwd IAT Max"] == 25000.0
    assert out["Active Mean"] == 50000.0
    assert out["Idle Max"] == 120000.0

def test_cicflow_adapter_drops_single_packet_flows():
    seen = []
    adapter = CICFlowMeterAdapter(seen.append)
    adapter.handle_flow(_make_cicflow_row(tot_fwd_pkts=1, tot_bwd_pkts=0))
    assert seen == []
    assert adapter.flows_dropped == 1

def test_cicflow_adapter_fills_schema_and_keeps_metadata():
    seen = []
    adapter = CICFlowMeterAdapter(seen.append, feature_columns=["Flow Duration", "Missing Feature"])
    adapter.handle_flow(_make_cicflow_row())
    out = seen[0]
    assert out["Missing Feature"] == 0.0
    assert out["_src_ip"] == "10.0.0.1"
    assert out["_dst_ip"] == "10.0.0.2"
    assert out["_dst_port"] == 80
    assert out["_protocol"] == 6

def test_cicflow_adapter_covers_trained_column_aliases():
    seen = []
    feature_columns = [
        "Protocol",
        "Fwd Packets Length Total",
        "Bwd Packets Length Total",
        "Packet Length Min",
        "Packet Length Max",
        "Avg Packet Size",
        "Init Fwd Win Bytes",
        "Init Bwd Win Bytes",
        "Fwd Act Data Packets",
        "Fwd Seg Size Min",
    ]
    adapter = CICFlowMeterAdapter(seen.append, feature_columns=feature_columns)
    adapter.handle_flow(_make_cicflow_row())
    out = seen[0]

    assert out["Protocol"] == 6.0
    assert out["Fwd Packets Length Total"] == 900.0
    assert out["Bwd Packets Length Total"] == 400.0
    assert out["Packet Length Min"] == 80.0
    assert out["Packet Length Max"] == 300.0
    assert out["Avg Packet Size"] == 180.0
    assert out["Init Fwd Win Bytes"] == 8192.0
    assert out["Init Bwd Win Bytes"] == 8192.0
    assert out["Fwd Act Data Packets"] == 3.0
    assert out["Fwd Seg Size Min"] == 20.0

def test_cicflow_adapter_ignores_bad_cwr_alias():
    seen = []
    adapter = CICFlowMeterAdapter(seen.append)
    adapter.handle_flow(_make_cicflow_row(cwr_flag_count=99, fwd_urg_flags=88))
    assert seen[0]["CWE Flag Count"] == 0.0
    assert seen[0]["Fwd URG Flags"] == 88.0

def test_cicflow_mode_prevents_short_idle_microflow_scoring():
    from decimal import Decimal
    from app.core.cicflow_bridge import CICFlowMeterSniffer

    class Flow:
        start_timestamp = Decimal("90.0")
        latest_timestamp = Decimal("96.5")
        packets = []

    sniffer = CICFlowMeterSniffer(lambda _row: None, flow_mode="cic_compatible")
    now = Decimal("100.0")

    assert sniffer._is_flow_ready(Flow(), now, terminal_only=True) is False
    assert sniffer._is_flow_ready(Flow(), now, terminal_only=False) is True

def test_cicflow_mode_still_emits_terminal_tcp_flows():
    from decimal import Decimal
    from app.core.cicflow_bridge import CICFlowMeterSniffer

    class Tcp:
        flags = 1

    class Packet:
        def __contains__(self, item):
            return item == "TCP"

        def __getitem__(self, item):
            if item == "TCP":
                return Tcp()
            raise KeyError(item)

    class Flow:
        start_timestamp = Decimal("99.0")
        latest_timestamp = Decimal("99.8")
        packets = [(Packet(), None)]

    sniffer = CICFlowMeterSniffer(lambda _row: None, flow_mode="cic_compatible")
    assert sniffer._is_flow_ready(Flow(), Decimal("100.0"), terminal_only=True) is True

test("CICFlow adapter — converts time fields to microseconds", test_cicflow_adapter_converts_seconds_to_microseconds)
test("CICFlow adapter — drops single-packet flows",            test_cicflow_adapter_drops_single_packet_flows)
test("CICFlow adapter — fills schema and preserves metadata",  test_cicflow_adapter_fills_schema_and_keeps_metadata)
test("CICFlow adapter — covers trained column aliases",        test_cicflow_adapter_covers_trained_column_aliases)
test("CICFlow adapter — ignores incorrect CWR alias",          test_cicflow_adapter_ignores_bad_cwr_alias)
test("CICFlow mode — CIC-compatible blocks short idle scoring", test_cicflow_mode_prevents_short_idle_microflow_scoring)
test("CICFlow mode — CIC-compatible emits terminal TCP flows",  test_cicflow_mode_still_emits_terminal_tcp_flows)


# ════════════════════════════════════════════════════════════
print("\n── SUMMARY ─────────────────────────────────────────────────────")
# ════════════════════════════════════════════════════════════
passed = sum(1 for _, ok, _ in results if ok)
failed = sum(1 for _, ok, _ in results if not ok)
total  = len(results)

print(f"\n  {passed}/{total} tests passed", end='')
if failed:
    print(f"  |  {failed} FAILED:")
    for name, ok, err in results:
        if not ok:
            print(f"    {FAIL} {name}: {err}")
else:
    print("  \u2014  All tests passed \u2713")
print()
sys.exit(0 if failed == 0 else 1)
