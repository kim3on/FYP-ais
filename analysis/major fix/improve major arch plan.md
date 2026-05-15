# Two-Layer AIS IDS Architecture — Assessment & Implementation Plan

## Problem Statement

Current detection performance is critically poor:
- **Recall: 11.8%** — only 1 in 8 attacks detected
- **FNR: 88.24%** — 7 out of 8 attacks missed
- **TP: 1,241** out of ~10,500 attacks

## Root Cause Analysis

After reading the full codebase, the core problem is **not** the architecture's concept — it's the **threshold calibration being far too conservative**:

```
# nsa.py line 94 — calibrate_threshold default
self.target_fpr = 0.01   # 1% FPR target

# pipeline.py line 172 — called with default
calibration = nsa.calibrate_threshold(X_cal, target_fpr=0.01)
```

With `target_fpr=0.01`, the threshold is set at the **99th percentile** of benign scores. This means the boundary between "normal" and "anomaly" is pushed so far out that only the most extreme outliers trigger — giving you 11.8% recall.

### Secondary Issues

| Issue | Location | Impact |
|-------|----------|--------|
| `_infer_attack_type` reads `attack_category` from the uploaded file during detection | [detection.py:191](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/detection.py#L191) | **Label leakage** — the model's "attack type" comes from the ground-truth label column, making it look like the model is classifying attacks when it's actually just reading the answer |
| No feature-space anomaly signal — detection relies solely on PCA-space distance | [nsa.py:336-339](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py#L336-L339) | PCA whitening compresses attack signatures; some attacks are close to benign in PCA space but extreme in individual features |
| `refresh()` still clips to `[0,1]` | [nsa.py:547](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py#L547) | Bug — breaks detector replacement after PCA |
| Training FPR is correct but detection metrics show the consequences | pipeline.py | The 1% FPR target is sound for precision, but catastrophic for recall in this feature space |

---

## Assessment of Your Plan

### ✅ Strengths (Things I Agree With)

1. **Binary-first detection** — Removing label-based attack classification from the detection path is the single most important fix. Right now `_infer_attack_type` reads `attack_category` from the CSV, which is pure label leakage. Your plan correctly moves this to a heuristic-only "Layer 2" that never sees labels.

2. **Two-layer separation** — Cleanly separating "is this anomalous?" from "what kind of attack might this be?" is architecturally sound and academically defensible.

3. **Self-boundary feature-space layer** — Adding per-feature BENIGN boundary checking in the *original* feature space (pre-PCA) catches attacks that PCA compresses away. This is the most impactful detection improvement.

4. **Metric assessment grading** (`target_met`, `prototype_acceptable`, `needs_improvement`) — Excellent for FYP reporting. Shows evaluators you understand your system's limitations.

5. **FPR target relaxation** — Moving from 1% to ~5% FPR is critical. The current 1% target is what's killing your recall.

### ⚠️ Improvements Needed

1. **Your plan says "desired Recall: 92-97%"** — This is aspirational but unlikely achievable with NSA alone on CIC-IDS-2017. Your "prototype acceptable: 85-92%" is more realistic. I'd set the **implementation target** at 70-85% recall for initial validation, then iterate.

2. **Self-boundary implementation detail** — Your plan mentions "per-feature BENIGN bounds or tail probabilities" but doesn't specify. I'll implement this as **per-feature percentile fences** (e.g., 1st and 99th percentile of benign training data), which is simple, explainable, and doesn't require additional model fitting.

3. **Attribution layer needs clearer scope** — The existing `_infer_attack_type` heuristic engine (Stage 2, lines 384-472) is already a solid flow-feature-only classifier. We just need to **stop feeding it the label** and restructure the output.

4. **Missing: the `_score_components` formula** — Currently `raw_scores = dist_to_self + det_scores`. The self-boundary signal should be added as a third component, not replace anything.

---

## User Review Required

> [!IMPORTANT]
> **FPR Target Change**: Moving from `target_fpr=0.01` (1%) to `target_fpr=0.05` (5%) will increase false positives by ~5x on benign traffic. For an academic prototype this is fine; for a production SOC it would be noisy. Your plan says 3-6% which is a good range. I'll use **5%** as default — confirm this is acceptable.

> [!IMPORTANT]  
> **Self-boundary approach**: I'll implement percentile fences (1st/99th percentile of each original feature from benign training data). Flows that violate multiple fences contribute to the anomaly score. This is simple and explainable. Your plan also mentions "tail probabilities" — should I go with the simpler percentile approach, or do you want a more sophisticated statistical model (e.g., Gaussian tail z-scores)?

> [!WARNING]
> **Retraining required**: After these changes, all existing model artifacts (`nsa_model.pkl`, `preprocessor.pkl`, `iso_model.pkl`) will be incompatible. Users must retrain.

---

## Proposed Changes

### Core Detection — Self-Boundary Layer

#### [NEW] [self_boundary.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/self_boundary.py)

New module implementing the AIS Self-Boundary detector:
- `SelfBoundaryDetector` class
- `fit(df_benign_raw)` — learns per-feature 1st/99th percentile fences from original (pre-PCA) benign features
- `score(df_raw)` → `(violation_count, violation_ratio, evidence_list)`
- `save()` / `load()` — joblib persistence alongside other artefacts
- Evidence output: `["Bwd Packet Length Std > BENIGN p99", "Total Bwd Packets < BENIGN p1"]`

---

### Core Detection — Detection Engine Refactor

#### [MODIFY] [detection.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/detection.py)

**Major changes:**
1. **New `AlertRecord` fields**: Replace `attack_type` as primary output with:
   - `is_anomaly: bool`
   - `anomaly_score: float`
   - `anomaly_sources: list[str]` — e.g. `["nsa_pca", "self_boundary"]`
   - `likely_attack_family: str` — from Layer 2 heuristics only
   - `attribution_confidence: str` — `"high"`, `"medium"`, `"low"`
   - `evidence: list[str]` — explainable per-feature violations
   - Keep `attack_type` as alias of `likely_attack_family` for backward compatibility

2. **Remove label leakage**: Line 191 (`cat = str(self._get(row, ['attack_category'], 'Unknown'))`) will no longer be passed to `_infer_attack_type`. The attribution layer uses **only** flow features.

3. **Integrate self-boundary**: `DetectionEngine.__init__` accepts an optional `SelfBoundaryDetector`. During detection, both NSA PCA-space and feature-space self-boundary signals are combined.

4. **Rename `_infer_attack_type` → `_attribute_attack`**: Clarify it's post-detection attribution, not classification. Remove Stage 1 (label-based) entirely. Keep Stage 2 (flow-feature heuristics) as the sole attribution mechanism.

---

### Core — Training Pipeline

#### [MODIFY] [pipeline.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/pipeline.py)

1. **Change default FPR target**: `target_fpr=0.05` (from 0.01)
2. **Train SelfBoundaryDetector**: Fit on benign training DataFrame (pre-PCA features), save alongside other artefacts
3. **Add self-boundary artefact path**: `SELF_BOUNDARY_PATH`
4. **Evaluate combined detection**: Score benign test rows through both NSA + self-boundary to report combined FPR
5. **Add `load_self_boundary()` convenience function**

---

### Core — NSA Model Fix

#### [MODIFY] [nsa.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py)

1. **Remove `[0,1]` clip in `refresh()`** (line 547): `np.clip(base + mutation, 0, 1)` → just `base + mutation`
2. **Default `target_fpr` → 0.05**: Update the class default
3. No other NSA changes — the core algorithm is sound

---

### Core — Evaluator

#### [MODIFY] [evaluator.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/evaluator.py)

1. **Add `assess_metric()` function**: Returns `"target_met"` / `"prototype_acceptable"` / `"needs_improvement"` / `"not_applicable"` based on the target bands from your plan
2. **Add `metric_assessment` to evaluation results**: Automatic grading alongside each metric
3. **Handle N/A metrics**: When a file slice has no attack labels, return Recall/FNR/Precision/F1 as `null` not `0%`

---

### State & Engine Wiring

#### [MODIFY] [state.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/state.py)

- `_build_engine()` now also loads `SelfBoundaryDetector` and passes it to `DetectionEngine`

#### [MODIFY] [pipeline.py load functions](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/pipeline.py)

- Add `load_self_boundary()` function
- Update `models_ready()` to check for self-boundary artefact

---

### Preprocessor

#### [MODIFY] [preprocessor.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/preprocessor.py)

- **Expose raw features for self-boundary**: Add `transform_raw()` method that returns scaled-but-not-PCA'd features alongside the PCA features. The self-boundary detector needs original feature space.
- Minor: ensure `transform()` and `transform_df()` can return both PCA and pre-PCA arrays

---

### Frontend

#### [MODIFY] [Detection.jsx](file:///c:/Users/kimeon/Desktop/ais-backend/frontend/src/pages/Detection.jsx)

- Display `likely_attack_family` in the attack-type column (no behavior change from user perspective)
- Add `attribution_confidence` badge next to attack type
- Show `anomaly_sources` as small tags (e.g., "NSA", "Self-Boundary")

#### [MODIFY] [Dashboard.jsx](file:///c:/Users/kimeon/Desktop/ais-backend/frontend/src/pages/Dashboard.jsx)

- Show `metric_assessment` badges next to each metric card
- Display self-boundary evidence in alert detail expansion

---

## Verification Plan

### Automated Tests
```powershell
# Compile check
python -m compileall app "validate and test"

# Backend test suite  
python "validate and test\test_backend.py"

# Frontend build
cd frontend && npm run build
```

### Manual Validation
1. **Train** on `Benign-Monday-no-metadata.parquet`
2. **Detect** on:
   - `DDoS-Friday-no-metadata.parquet` (rows 20000-30000)
   - `DoS-Wednesday-no-metadata.parquet`
   - `Portscan-Friday-no-metadata.parquet`  
   - `Bruteforce-Tuesday-no-metadata.parquet`
3. **Confirm**:
   - Recall > 50% (significant improvement from 11.8%)
   - Binary metrics reported separately from attack attribution
   - `attack_category` label never used during detection
   - `likely_attack_family` comes from flow-feature heuristics only
   - `metric_assessment` grades shown for each metric
   - Evidence strings explain why each flow was flagged
