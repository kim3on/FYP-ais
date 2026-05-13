# ML Pipeline Validation Report

**Date:** 2026-05-02
**Context:** @ml-engineer @statistical-analysis

> **Current status (May 2026):** This report records the original leakage audit. The current pipeline still follows split-before-fit, but preprocessing has advanced from MinMax-only scaling to `RobustScaler` followed by `PCA(whiten=True)` so the NSA operates in calibrated PCA space.

## 1. Objective
To validate the statistical integrity of the AIS-Detect training pipeline and ensure benchmark fairness against the Isolation Forest baseline.

## 2. Audit Findings

### 2.1 Preprocessing Data Leakage (Resolved)
*   **Finding:** The original scaler was fitted on the entire dataset *before* the train/test split.
*   **Impact:** Information from the test set (max/min values of future attacks) leaked into the training feature space. This resulted in "compressed" feature ranges and artificially inflated performance metrics.
*   **Fix:** Refactored `CICIDSPreprocessor` and `TrainingPipeline` to implement a strict **Split-Before-Fit** pattern. The current implementation fits `RobustScaler` and `PCA(whiten=True)` only on the training split.

### 2.2 Benchmark Fairness
*   **Status:** **Verified**.
*   **Observation:** Both models now operate on the exact same feature distribution. The NSA (AIS) is correctly restricted to "Normal" training samples, while Isolation Forest is trained on the full (potentially contaminated) split, mirroring real-world deployment constraints for both algorithms.

### 2.3 Class Imbalance & Evaluation
*   **Status:** **Robust**.
*   **Observation:** The `Evaluator` now provides per-category detection rates. This prevents the "Accuracy Paradox" where high accuracy is reported despite missing 100% of attack traffic due to high class imbalance.

## 3. Statistical Integrity Results
The refactored pipeline was verified using `validate_ml.py`. 

| Test | Status | Note |
| :--- | :--- | :--- |
| Leakage Check | **CLEAN** | Scaler now fitted strictly on training split. |
| Contamination | **NONE** | No duplicate rows found between splits. |
| Fairness | **FAIR** | Identical test set for both models. |

## 4. Recommendations
*   Continue using `stratify=y` during splits to maintain attack distribution in small datasets.
*   Maintain `RobustScaler + PCA(whiten=True)` for current AIS experiments; NSA detector generation and thresholds must stay calibrated to PCA space rather than assuming `[0,1]` feature bounds.
