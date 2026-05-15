# Mathematical Fix Plan For AIS-Detect Backend

## Summary
Implement the five math fixes without changing the core AIS architecture: make deployed thresholds match calibrated thresholds, replace fragile Gaussian Self-Boundary math with quantile fences, use conformal calibration for finite-sample control, expose detector/source decomposition, and make leakage-prone preprocessing explicit.

Default chosen: use **distribution-free quantile fences** for Self-Boundary.

## Key Changes

### 1. Calibration And Threshold Correctness
- Add one shared conformal threshold helper:
  - Input: benign scores, `target_fpr`.
  - Rule: sort scores, choose `k = ceil((n + 1)(1 - target_fpr))`, clamp to valid index, classify with `score > threshold`.
  - Return threshold, observed FPR, rank index, sample count, and reliability label.
- Use this helper in:
  - NSA threshold calibration.
  - Fused AIS threshold calibration.
  - Self-Boundary weighted threshold calibration.
- Make Self-Boundary inference use the same strict rule as calibration:
  - `anomaly ⇔ weighted_score > weighted_threshold`
  - no `>=` for calibrated thresholds.
- Add calibration reliability:
  - `<200` benign calibration rows: `experimental`.
  - `200-999`: `prototype`.
  - `>=1000`: `stable`.
  - Keep training allowed, but warnings and result JSON must clearly report reliability.

### 2. Self-Boundary Math Upgrade
- Replace the default Gaussian mean/std boundary with quantile fences in `SelfBoundaryDetector`.
- Fit per-feature benign bounds:
  - `lower_j = Q_j(0.005)`
  - `upper_j = Q_j(0.995)`
  - use finite numeric values only, with missing/non-finite values treated consistently with current preprocessing.
- Score a row by rarity-weighted fence violations:
  - `violation_j(x) = x_j < lower_j - eps_j OR x_j > upper_j + eps_j`
  - `w_j = -log(smoothed benign violation rate_j)`
  - normalize weights so `Σw_j = 1`.
- Keep a continuous score:
  - binary violation contribution plus clipped normalized excess outside the fence.
  - use robust scale from IQR/MAD with epsilon fallback.
- Preserve backward compatibility for old saved artifacts:
  - if quantile fields are missing, load old Gaussian fields and mark `boundary_mode = "gaussian_zscore_legacy"`.
- Update summaries to report:
  - `boundary_mode`
  - lower/upper quantiles
  - number of constant/near-constant features
  - weighted threshold and calibration reliability.

### 3. Detector Source Decomposition
- Add a non-breaking NSA method that returns decision components for a batch:
  - `v_detector_match`
  - `self_gap_match`
  - `nsa_score_match`
  - `fusion_score_match`
  - raw `distance`, `detector_score`, and `fused_score`.
- Keep final decision unchanged:
  - `anomaly = v_detector_match OR fused_score > fusion_threshold`
  - NSA-only remains `v_detector_match OR anomaly_score > score_threshold`.
- Update training labelled verification and detection output to include source metrics:
  - detector recall/FPR
  - self-gap recall/FPR
  - fusion-only recall/FPR
  - overlap counts for `D`, `G`, and `F`.
- Update alert `anomaly_sources` to use clearer values:
  - `v_detector`
  - `self_gap`
  - `self_boundary`
  - `score_fusion`
- Keep UI/API compatibility by treating these as display strings; no schema-breaking field removal.

### 4. Leakage-Safe Preprocessing API
- Make `fit_transform()` explicit about unsafe mixed-dataset fitting:
  - If labels contain both benign and attack rows, require `allow_unsafe_full_dataset_fit=True`.
  - Otherwise raise a clear `ValueError` explaining split-before-fit.
- Add a clearly named legacy/test helper:
  - `fit_transform_unsafe_single_dataset(...)`
  - internally calls the same behavior with the explicit unsafe flag.
- Keep the main training pipeline unchanged in principle:
  - it already uses `fit(df_train_raw)` then `transform_df(...)`.
- Update tests that intentionally use the old shortcut to call the explicit unsafe helper or pass the explicit flag.

### 5. Validation Script And Metric Semantics
- Fix `validate_ml.py` so it reads labelled metrics from:
  - `post_run_labelled_verification`
  - not `nsa_eval['f1']` or `nsa_eval['recall']`.
- Keep benign-only training metrics as `None` for precision/recall/F1/FNR.
- Add assertions that:
  - unsupervised training metrics do not report attack metrics.
  - labelled verification is available when attack rows exist.
  - threshold analysis remains report-only.
  - source decomposition fields are present.

## Test Plan
- Unit tests:
  - Self-Boundary threshold uses `>` consistently and does not flag every zero-score row when threshold is `0`.
  - Quantile fences flag synthetic out-of-fence samples and pass in-fence benign samples.
  - Legacy Gaussian Self-Boundary artifacts still load through compatibility fields.
  - Conformal threshold helper returns expected rank/threshold for small known score arrays.
- Pipeline tests:
  - scaler/PCA still fit only on benign training rows.
  - NSA/fusion/Self-Boundary calibration summaries include reliability metadata.
  - small calibration sets produce warnings but do not crash.
  - labelled verification reports recall/FNR/FPR separately from benign-only training metrics.
- Detection tests:
  - batch detection includes source-decomposed metrics when labels exist.
  - alerts contain detailed `anomaly_sources`.
  - final labels remain unchanged for equivalent scores except the fixed Self-Boundary `>=` bug.
- Regression tests:
  - `validate and test/test_backend.py`
  - `validate and test/validate_security.py`
  - `validate and test/validate_ml.py` with `PYTHONPATH` set to repo root.

## Assumptions
- This remains an academic/FYP prototype, not a production SOC detector.
- Training should not fail only because calibration rows are small; it should mark the calibration as experimental and warn clearly.
- Quantile fences are preferred over MAD z-scores because CIC flow features are skewed, heavy-tailed, and zero-inflated.
- Public behavior should be backward compatible where practical, but unsafe mixed-data `fit_transform()` usage should become explicit rather than silent.
