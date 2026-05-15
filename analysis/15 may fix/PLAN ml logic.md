# Unsupervised NSA Improvement Plan

## Summary
Keep AIS-Detect strictly unsupervised for fitting, calibration, and threshold selection. Attack labels will be used only after predictions are complete for report-only validation of recall, FNR, FPR, precision, F1, and per-attack-family detection rate.

The main goal is to fix the current failure mode where the saved model gets `100%` recall only by flagging every benign row as anomalous.

## Key Changes
- Preserve the existing split-before-fit rule:
  - Fit `RobustScaler`, PCA, Self-Boundary, NSA detectors, score scales, and thresholds only on benign training/calibration rows.
  - Never use attack rows to tune `r`, `r_s`, detector generation, fusion weights, component scales, or thresholds.
- Add report-only labelled evaluation after the model is frozen:
  - Use held-out benign rows plus attack rows from the uploaded dataset.
  - Compute recall, FNR, FPR, precision, F1, confusion matrix, and per-category detection rates.
  - Mark these metrics clearly as `post_run_labelled_verification`.
- Add minimum data-quality guards:
  - Warn or fail training when benign rows are too few for meaningful calibration.
  - Default minimum: `>= 1000` benign rows recommended; hard fail below `100` benign rows.
  - Surface a warning when calibration/test sets have fewer than `200` benign rows.

## NSA And Scoring Changes
- Make mature V-detectors the primary anomaly mechanism:
  - Final anomaly decision should be: `detector_match OR fused_score > benign_calibrated_threshold`.
  - Self-gap and self-boundary remain secondary evidence.
- Increase default NSA capacity:
  - `max_detectors`: default `3000`.
  - `max_attempts`: default `100000`.
  - Keep user override support.
- Improve detector generation in PCA-whitened space:
  - Do not assume `[0,1]` bounds.
  - Generate candidates from benign PCA-space boundary/tail regions using benign quantiles and nearest-neighbour distance statistics.
  - Reject candidates inside self tolerance and reject excessive detector overlap.
- Rebalance fusion weights so Self-Boundary does not dominate:
  - Default weights:
    ```python
    {
        "detector": 0.40,
        "distance": 0.25,
        "density": 0.20,
        "self_boundary": 0.15,
    }
    ```
  - Calibrate all component scales from benign calibration rows only.
  - Use robust scale floors so tiny benign Self-Boundary scores do not cause fused-score saturation.

## Validation And Reporting
- Training result should show two separate sections:
  - `unsupervised_benign_validation`: benign FPR, self-intrusion rate, silhouette.
  - `post_run_labelled_verification`: recall, FNR, precision, F1, FPR, TP/FP/TN/FN, per attack family.
- Threshold analysis remains report-only:
  - It may show what threshold would improve recall/FNR/FPR.
  - It must not update saved model artifacts.
- Update dashboard wording to avoid implying production SOC readiness:
  - Position results as academic prototype validation.
  - Keep accuracy secondary and emphasize recall/FNR/FPR.

## Test Plan
- Unit tests:
  - Confirm scaler and PCA are fitted only on benign training rows.
  - Confirm attack labels are unavailable to NSA fit/calibration code paths.
  - Confirm detector generation works in PCA-whitened values outside `[0,1]`.
  - Confirm final prediction flags samples matched by V-detectors even if fused score is below threshold.
- Integration tests:
  - Train on a mixed CIC-IDS-2017 sample and verify saved artifacts are produced.
  - Verify labelled metrics are absent when no labels exist.
  - Verify labelled metrics appear only after prediction when labels exist.
- Evaluation scenarios:
  - Monday benign-only validation for FPR/self-intrusion.
  - Mixed CIC-IDS-2017 days for recall/FNR by attack family.
  - Small dataset case to confirm warnings/failures are clear.

## Assumptions
- The project title requires unsupervised detection, so labels are allowed only for post-run evaluation.
- The target operating preference is high recall and low FNR, while keeping FPR visibly reported.
- Default target FPR remains `0.05`, but the UI/API may allow `0.03` to `0.15` for unsupervised benign calibration experiments.
