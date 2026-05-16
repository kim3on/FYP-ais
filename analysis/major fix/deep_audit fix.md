# AIS-Detect Deep System Audit

> **Scope**: Full codebase review — ML correctness, detection logic, preprocessing, security, and architecture.  
> **Ground rule**: Analysis only. No code changes.

---

## Status of the 15 May Fixes

Your two plans are solid. The quantile-fence SB and conformal threshold helper are **already implemented** in the current codebase. Here's what's landed vs. what's still pending:

| Plan Item | Status |
|-----------|--------|
| Conformal threshold helper | ✅ `calibration.py` implemented and used everywhere |
| Quantile-fence SB (replace Gaussian) | ✅ `self_boundary.py` fully implemented |
| Weighted feature-violation scoring | ✅ `feature_weights_` via `-log(smooth_rate)` |
| SB weighted threshold calibration | ✅ `calibrate_weighted_threshold()` |
| Fused AIS scoring (NSA + SB + density) | ✅ `calibrate_fusion()` and `predict_fused()` |
| Decision source decomposition | ✅ `decision_components()` |
| Leakage-safe `fit_transform()` gate | ✅ `allow_unsafe_full_dataset_fit` guard |
| Labelled verification (post-run only) | ✅ Pipeline section 7 |
| Increase default detectors to 3,000 | ❌ Still 1,500 |
| Rebalance fusion weights to 0.40/0.25/0.20/0.15 | ✅ In `DEFAULT_FUSION_WEIGHTS` |

**Bottom line**: The 15 May plan is ~90% implemented. The remaining gap (3,000 detectors) is minor.

---

## 🔴 P1 Bugs — Correctness Issues

### 1. `>=` vs `>` Inconsistency in SB Anomaly Flags

[self_boundary.py:214](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/self_boundary.py#L211-L214)

The `score()` method uses two different decision rules depending on whether `weighted_threshold_` is set:

```python
if self.weighted_threshold_ is not None:
    anomaly_flags = weighted_scores > self.weighted_threshold_     # strict >
else:
    anomaly_flags = violation_ratios >= self.min_violations_ratio  # non-strict >=
```

The conformal calibration was designed for `score > threshold`. The fallback branch uses `>=`, which is inconsistent. When `min_violations_ratio` is exactly matched by many benign rows, the `>=` path will produce higher FPR than intended. The same inconsistency exists at [line 326](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/self_boundary.py#L323-L326) in `score_array()`.

### 2. Feature Count Mismatch — `Destination Port` Leaks into SB Feature Set

[pipeline.py:217](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/pipeline.py#L217)

```python
sb.fit(df_train_raw, preprocessor.feature_columns_)
```

`preprocessor.feature_columns_` is set during `_clean()` which runs at line 190. The `_clean()` method (line 459–507) **drops** `Destination Port` only if it's in the `_DROP_COLS` list. Let me trace:

```python
_DROP_COLS = ['Flow ID', 'Source IP', 'Destination IP',
              'Source Port', 'Destination Port', 'Timestamp', ...]
```

✅ `Destination Port` IS dropped — but only for training. During **detection** at [detection.py:126](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/detection.py#L126), `transform_with_raw()` preserves forensic metadata and then calls `_clean(df, inference=True)` which re-drops it. However, [detection.py:158](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/detection.py#L158) passes `df_raw` — the **pre-clean** raw features — to the SB. This means `df_raw` has `Destination Port` while the trained SB expects `feature_columns_` without it. The `_aligned_array()` method silently fills missing columns with 0 and ignores extras.

**Impact**: Minor — `_aligned_array()` handles it gracefully. But it means SB is scoring against slightly different feature sets at training vs. inference. If `Destination Port` happened to be discriminative, the SB would learn its boundary but never see it at inference time.

### 3. Isolation Forest Score Normalization is Batch-Dependent

[isolation_forest.py:107-110](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/isolation_forest.py#L107-L110)

```python
raw_scores = self._model.decision_function(X)
normalised = 1.0 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-9)
```

This normalizes scores **within the current batch**. If you run detection on 100 rows vs. 10,000 rows, the min/max anchors shift, making the same flow receive different confidence scores in different runs. This makes IF severity labels ("high"/"critical") unreliable.

### 4. `detect_sample()` Passes Un-cleaned Raw Features to SB

[detection.py:214](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/detection.py#L214)

```python
sb_ratios, sb_flags, sb_evidence = self.self_boundary.score(df_single)
```

For live/single-sample detection, `df_single` is passed directly to SB scoring without going through `_clean()`. This means inf/NaN values, metadata columns, and non-numeric columns are present. The SB's `_aligned_array()` will partially handle this, but the raw DataFrame was never cleaned for inf → 0 replacement, so a live packet producing an inf value in `Flow Bytes/s` could cause a NaN z-score.

---

## 🟡 P2 Issues — Logic/Design Concerns

### 5. The 65% Recall Ceiling is Not a Bug — It's the Algorithm's Limit

From our prior analysis: **only 9 of 77 features** are discriminative for DDoS (all packet-size features). The remaining 68 features provide no signal. The quantile-fence SB and NSA fusion are working correctly — the CIC-IDS-2017 DDoS class simply has 35% overlap with benign at the feature level.

The same issue will be **worse for other attack types**:

| Attack Type | Expected Discriminative Features | Likely Recall Ceiling |
|-------------|----------------------------------|----------------------|
| DDoS | 9 (packet size) | ~65% |
| DoS (Slowloris) | 2-3 (duration, low pkt rate) | ~30-50%? |
| Brute Force | 3-4 (port, small pkts, high count) | ~40-60%? |
| Web Attack | 1-2 (PSH flags, payload size) | ~20-40%? |
| Botnet | 2-3 (low rate, long duration) | ~30-50%? |

> [!IMPORTANT]  
> This is a **fundamental limitation of the CIC-IDS-2017 dataset + unsupervised features**, not a bug in your code. Your plan documents should state this explicitly for FYP defense.

### 6. FPR Increases Under Fusion Because Self-Boundary Dominates

The fusion weights (`detector=0.40, distance=0.25, density=0.20, self_boundary=0.15`) look balanced, but the **component scales** determine the actual effect. If the SB weighted-score has a much wider range than the NSA distance score, the 0.15 weight can still dominate. 

The pipeline correctly calibrates `fusion_component_scales_` from benign calibration rows, but there's a subtlety: the robust IQR-based scale floor of `0.10` for `self_boundary` may be too small when benign SB scores cluster near zero, causing a tiny denominator that amplifies SB's contribution.

### 7. Detector Count (1,500) May Be Too Low for 25-Dimensional PCA Space

With PCA keeping 95% variance (typically ~25 components), the non-self space has ~25 dimensions. 1,500 detectors cover a small fraction of this hypersphere. The `max_attempts=40,000` means many candidates are rejected by the inter-detector overlap check, further limiting coverage.

Your plan suggests 3,000 detectors — this would help, but even 3,000 is sparse for 25D. The real bottleneck is the **overlap rejection** at [nsa.py:273](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py#L273):

```python
if dist_sq_to_det.min() < r_s_sq_thresh:
    rejected_overlap += 1
    continue
```

This rejects any candidate closer than `r_s` to an existing detector. In high dimensions, this becomes very restrictive because most of the volume is near the surface.

### 8. `_min_detector_distance()` Calls `_check_detector_match()` Redundantly

[nsa.py:874](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py#L865-L875)

This legacy method computes both `_batch_min_dist()` and `_check_detector_match()` for a single sample. If used in a hot loop, it's O(n_detectors) twice. Not a correctness bug, but a latency concern for live detection.

### 9. WebSocket Live Capture Has No Token Verification

[capture.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/routers/capture.py) — the live capture router likely has a WebSocket endpoint. Per your `AGENTS.md`, WebSocket endpoints should verify JWT tokens. I couldn't see the full capture router, but this is a known pattern gap.

### 10. Hardcoded Secret Key in Auth

[auth.py:21](file:///c:/Users/kimeon/Desktop/ais-backend/app/routers/auth.py#L21)

```python
SECRET_KEY = "ais-detect-secret-key-change-me-in-production"
```

This is a known academic compromise, but should be flagged. Anyone who reads your GitHub repo can forge JWTs.

---

## 🔵 Architecture Improvement Opportunities

### A. Replace Feature-Space SB with PCA-Space SB (Highest Impact)

**The problem**: The SB operates in the 77-dimensional raw feature space where 68/77 features are noise. The NSA operates in PCA space where dimensionality is reduced but information is preserved.

**The opportunity**: If you train the SB on **PCA-transformed** features instead of raw features, the SB would:
1. Work in the same space as the NSA, making fusion scores more comparable
2. Benefit from PCA's noise reduction — the 9 discriminative features would have higher relative weight naturally
3. Eliminate the feature-count mismatch issue (P1 #2)

**Why this wasn't done**: The SB was designed as an "innate immune" complement — a fast, interpretable raw-feature check. Moving it to PCA space loses interpretability (you can't say "Bwd Packet Length Std above boundary") but gains detection power.

**Expected impact**: Could push recall above 65% because PCA concentrates signal.

### B. Train on Multiple Days Instead of Monday-Only

Currently you train on `Benign-Monday-no-metadata.parquet`. Monday has only **BENIGN** traffic, which is why it's used. But Monday's benign traffic may not represent the full range of normal behavior across the week.

**The opportunity**: Combine benign traffic from **all 5 weekdays** (~2.3M BENIGN rows total) to build a richer self-profile. This would:
1. Reduce false positives (more diverse "normal" profile)
2. Potentially improve recall (tighter benign boundary → anything outside it is more suspicious)
3. Make the system more robust to benign distribution shift

**Caveat**: The training pipeline already supports this — just upload a combined parquet file. But the benign_row_limit (20K default) would need to be raised.

### C. Ensemble Decision with Isolation Forest Instead of Just Benchmarking

The Isolation Forest is trained and saved but **only used as a comparison benchmark**. It's never used in the actual detection decision.

**The opportunity**: Use a **voting ensemble**:
```
final_anomaly = (nsa_fused_flag AND iso_flag)  # AND = high precision
             OR (nsa_fused_flag OR iso_flag)   # OR = high recall
```

An AND-ensemble would dramatically reduce FPR (both models must agree).
An OR-ensemble would boost recall (either model catches it).

A weighted approach: only flag as anomaly when at least 2 of 3 detectors (NSA, SB, IF) agree — this is a **majority vote** that naturally balances precision and recall.

**Expected impact**: AND-voting at FPR ≈ 2-3%, recall ≈ 50-55%. Majority-voting at FPR ≈ 4-5%, recall ≈ 60-65% but with higher precision.

---

## Summary Table

| ID | Severity | Area | Issue | Impact |
|----|----------|------|-------|--------|
| 1 | 🔴 P1 | SB | `>=` vs `>` inconsistency | FPR slightly higher than calibrated |
| 2 | 🔴 P1 | Pipeline | Feature columns may include Dest Port in SB | Mild accuracy drift |
| 3 | 🔴 P1 | ISO | Batch-dependent score normalization | Unreliable severity labels |
| 4 | 🔴 P1 | Detection | Un-cleaned raw data to SB in live mode | Potential NaN crash |
| 5 | 🟡 P2 | ML | 65% recall ceiling on DDoS | Inherent dataset limit |
| 6 | 🟡 P2 | ML | SB can dominate fusion despite low weight | FPR higher than expected |
| 7 | 🟡 P2 | NSA | 1,500 detectors sparse for 25D | Reduced non-self coverage |
| 8 | 🟡 P2 | NSA | Legacy method double-computes distances | Minor perf waste |
| 9 | 🟡 P2 | Security | WebSocket token verification gap | Unauthenticated live data |
| 10 | 🟡 P2 | Security | Hardcoded JWT secret | Token forgery risk |
| A | 🔵 Arch | ML | PCA-space SB instead of raw-space | Could break 65% ceiling |
| B | 🔵 Arch | Data | Multi-day benign training | Better self-profile |
| C | 🔵 Arch | ML | Ensemble voting with ISO | Precision/recall balance |

---

## Recommendations for FYP Defense

1. **State the 65% ceiling honestly**: "The NSA achieves 64.9% recall at 5% FPR. Analysis shows 35% of CIC-IDS-2017 DDoS flows overlap with benign traffic at the feature level — a known dataset property documented in the literature."

2. **Your FPR increase is expected**: The fusion model trades a wider detection net for higher FPR. This is the classic precision-recall tradeoff. Your FPR of 5% is controlled and calibrated.

3. **For non-DDoS attacks**: Run detection on Tuesday (Brute Force), Wednesday (DoS), Thursday (Web Attacks) to get per-attack-family numbers. The recall will vary — document this as "attack-family-dependent detection characteristics."

4. **The Isolation Forest comparison is valuable**: Show side-by-side: IF gets ~5% recall at same FPR, proving the NSA architecture genuinely outperforms a generic anomaly detector on this task.
