# AIS-Detect Mathematical Improvement Log

## 2026-05-23 - Step 1 Reverted: Labelled FPR Budget Diagnostics

### Reason
The FPR-budget diagnostic change was reverted at user request because the result appeared worse after the implementation.

### Reverted changes
- Removed `fpr_budget` metadata from `threshold_analysis()`.
- Removed `FPR Budget Used` and `FP Budget Left` from the Threshold Tradeoff Summary UI.
- Removed backend assertions that expected `fpr_budget` in threshold-analysis output.

### Current state
The earlier report-only 15% labelled FPR cap remains active:

```text
maximize Recall
subject to FPR <= 0.15
```

The saved benign-calibrated NSA/fusion threshold remains unchanged.

### Validation
- `validate and test/test_backend.py`: passed, `52/52 tests passed`.
- `npm.cmd run build`: passed.

## 2026-05-23 - Steps 5 and 6 Reverted

### Reason
The detector geometry and benign-data-cap experiment was reverted at user request because the result got worse.

### Reverted changes
- Removed recall geometry profile training changes.
- Removed the benign-calibrated V-detector confidence gate.
- Restored the default BENIGN row cap to 20,000.
- Removed benign calibration data summary fields from training result, UI, and tests.

### Current state
The earlier report-only 15% labelled FPR recommendation remains active:

```text
maximize Recall
subject to FPR <= 0.15
```

The saved benign-calibrated NSA/fusion threshold remains unchanged.

### Validation
- `py_compile` for `app/models/nsa.py`, `app/core/pipeline.py`, `app/routers/training.py`, and `app/core/evaluator.py`: passed.
- Non-mutating rollback signature check: passed.
- Non-mutating 15% report-only threshold-analysis check: passed.
- `npm.cmd run build`: passed.

## 2026-05-24 - Replace Weighted Fusion With Pure NSA

### Goal
Use a simpler, academically defensible final AIS decision rule.

### Mathematical change
The active NSA decision is now:

```text
anomaly(x) = VDetectorMatch(x) OR distance_to_nearest_self(x) > tau
```

The threshold `tau` is calibrated from BENIGN rows only against the full final rule:

```text
mean(VDetectorMatch OR self_distance > tau) <= target_fpr
```

### Files changed
- Replaced active weighted-fusion training and detection with pure NSA self-gap calibration.
- Kept Self-Boundary as supporting evidence and reporting metadata only.
- Added forced-positive threshold analysis so detector matches remain positive while self-gap thresholds are swept.
- Updated tests and UI wording from fusion threshold to NSA self-gap threshold.

### Validation
- `py_compile` for `app/models/nsa.py`, `app/models/self_boundary.py`, `app/core/pipeline.py`, `app/core/detection.py`, and `app/core/evaluator.py`: passed.
- `validate and test/test_backend.py`: passed, `56/56 tests passed`.
- `validate and test/validate_security.py`: passed, `4 tests passed`.
- `validate and test/validate_ml.py`: passed.
- `npm.cmd run build`: passed.
