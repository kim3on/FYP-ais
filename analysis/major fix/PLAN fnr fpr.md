# Strict Unsupervised AIS Detection Improvement Plan

## Summary
Improve detection quality while keeping the project genuinely unsupervised. The model will train, scale, score, and calibrate only from BENIGN traffic. Attack labels will be used only after the detector is frozen to report recall/FNR/FPR for the final evaluation.

Target for final labelled report:
- Recall ≥ 90%
- FNR ≤ 10%
- FPR ≤ 5%

## Key Changes
- Change default benign calibration target from `1%` FPR to `5%` FPR.
  - Store `target_fpr: 0.05` in the trained NSA artifact.
  - UI should show `Target FPR 5.00%`.
- Replace the current single anomaly score with an unsupervised ensemble score:
  - nearest-self distance score,
  - k-nearest-self density score,
  - V-detector match depth score.
  - Normalize each score using BENIGN calibration quantiles only.
  - Final anomaly score = weighted combination, default weights: distance `0.45`, density `0.35`, detector `0.20`.
- Improve self profiling without labels:
  - Fit scaler/PCA only on BENIGN training rows.
  - Make PCA optional and default to no whitening for detection runs, because whitening can hide sparse attack-specific flow signals.
  - Keep metadata out of features, but preserve flow/statistical feature columns consistently.
- Calibrate threshold only on BENIGN calibration rows:
  - threshold = 95th percentile of final benign ensemble scores.
  - observed benign FPR should be near 5%.
  - labels must not affect threshold, weights, feature selection, PCA setting, or detector generation.
- Add final evaluation reporting only after detection:
  - If uploaded detection data has labels, show `Post-run Labelled Verification`.
  - Include recall, FNR, FPR, precision, F1, true attacks caught, attacks missed, false alarms, normal passed.
  - Add a note: labels were used only after detection to score the frozen unsupervised output.

## Implementation Details
- Backend model:
  - Extend `NegativeSelectionDetector` with `score_components(X)` returning distance, density, detector, and final score.
  - Store benign calibration quantiles and ensemble weights in `calibration_`.
  - Use calibrated final score for `predict`, `predict_with_scores`, and `predict_with_details`.
- Training pipeline:
  - Keep BENIGN-only train/calibration/test split.
  - Fit preprocessing on BENIGN train only.
  - Fit NSA on BENIGN train only.
  - Calibrate component quantiles and final threshold on BENIGN calibration only.
  - Save `validation_mode: strict_unsupervised_benign_calibrated`.
- API/UI:
  - Add visible training summary fields: `Target FPR`, `Observed Benign FPR`, `Threshold`, `Score Mode: Ensemble`.
  - Add FNR to labelled detection verification.
  - Keep row limit behavior already fixed.

## Test Plan
- Unit/smoke tests:
  - Train NSA on synthetic benign data and verify calibration threshold gives about 5% benign flags.
  - Verify `score_components` returns finite values for all rows.
  - Verify prediction uses saved calibrated threshold.
- App checks:
  - `python -m compileall app`
  - `npm run build` from `frontend`
- Final fixed-protocol benchmark:
  - Train once on BENIGN Monday only.
  - Without changing thresholds after seeing labels, run labelled detection on all CICIDS attack-day files.
  - Report per-file and aggregate recall, FNR, FPR, precision, F1.
  - Pass target only if aggregate recall ≥ 90%, FNR ≤ 10%, and FPR ≤ 5%.

## Assumptions
- Supervised learning remains denied.
- Attack labels are allowed only for final reporting, not tuning.
- Default operating point is `5%` benign FPR to improve recall while keeping false alarms defensible.
- If the final benchmark misses the target, the result must be reported honestly; no label-driven retuning is allowed under the strict unsupervised rule.
