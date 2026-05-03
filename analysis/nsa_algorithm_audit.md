# NSA Algorithm Audit — Mathematically Critical Review

**Date:** 2026-05-02  
**Scope:** Full algorithm validation across 15 audit dimensions  
**Files Audited:**  
- [nsa.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py)  
- [isolation_forest.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/isolation_forest.py)  
- [pipeline.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/pipeline.py)  
- [preprocessor.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/preprocessor.py)  
- [detection.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/detection.py)  
- [evaluator.py](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/evaluator.py)  
- [test_backend.py](file:///c:/Users/kimeon/Desktop/ais-backend/test_backend.py)

---

## Verdict Summary

| # | Audit Dimension | Verdict | Severity |
|---|---|---|---|
| 1 | Self dataset definition | ✅ Correct | — |
| 2 | Detector generation method | ⚠️ Flawed assumption | Medium |
| 3 | Detector radius / affinity threshold | 🔴 Critical issue | **Critical** |
| 4 | Matching function correctness | ✅ Correct | — |
| 5 | Self tolerance handling | ⚠️ Weakness | Medium |
| 6 | Detector coverage gaps | 🔴 Mathematically inevitable | **High** |
| 7 | Detector overlap redundancy | ⚠️ Unmanaged | Low |
| 8 | FP / FN tradeoff | 🔴 Not controllable | **High** |
| 9 | Detector aging / replacement | 🔴 Missing entirely | **High** |
| 10 | Computational complexity | ✅ Well-optimized | — |
| 11 | Training data contamination | ⚠️ Structural risk | Medium |
| 12 | Feature normalization | ✅ Correct | — |
| 13 | Classification decision boundary | ⚠️ Brittle | Medium |
| 14 | Biological NSA fidelity | ⚠️ Partial | Medium |
| 15 | Fairness vs. Isolation Forest | 🔴 Unfair comparison | **High** |

---

## 1. Self Dataset Definition Correctness ✅

**Code:** [pipeline.py:132](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/pipeline.py#L132)

```python
X_train_normal = X_train[y_train == 0]
nsa.fit(X_train_normal)
```

**Assessment:** **Correct.** The NSA trains exclusively on BENIGN-labeled samples from the training split. This is the canonical self-set definition for Negative Selection: self = normal traffic.

**Minor concern:** The label encoding at [preprocessor.py:306](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/preprocessor.py#L306) uses string comparison:

```python
y = (raw_labels.str.upper() != NORMAL_LABEL.upper()).astype(int).values
```

This is correct but fragile — any label not exactly matching `"BENIGN"` (case-insensitive) becomes attack. If the dataset contains novel benign sub-labels (e.g., `"BENIGN-INTERNAL"`), they would be misclassified as attacks, contaminating ground truth.

---

## 2. Detector Generation Method ⚠️ Flawed Assumption

**Code:** [nsa.py:106-131](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py#L106-L131)

The implementation uses a **two-phase heuristic**:

| Phase | Range | Strategy |
|-------|-------|----------|
| Phase 1 (first 50%) | Uniform `[0, 1]^d` | Broad exploration |
| Phase 2 (second 50%) | Gaussian mutation from self-boundary | Targeted placement |

### Mathematical Issue: Phase 1 is Virtually Useless in High Dimensions

In `d = 77` dimensions (CIC-IDS-2017 feature count), a uniformly random point in `[0,1]^77` has expected distance from the centroid of `(0.5, ..., 0.5)`:

$$E[\|x - c\|] = \sqrt{\sum_{i=1}^{77} E[(x_i - 0.5)^2]} = \sqrt{77 \cdot \frac{1}{12}} \approx 2.533$$

The **normalized** distance (dividing by `√77 ≈ 8.775`) is approximately `0.289`.

If `r = 0.5` (the default), virtually **every** random candidate in `[0,1]^77` will pass the negative selection check because the concentration of measure phenomenon means random points are almost always far from any self-sample cluster. This means:

> **Phase 1 does not actually perform meaningful negative selection — it's rubber-stamping random noise as "detectors."**

The 50% of detectors generated this way are essentially random vectors that happen to not overlap with self. They will fire on random normal traffic that is also distant from the self-reference sample (which is capped at 5,000).

### Phase 2 is Better But Still Problematic

```python
base = ref[rng.integers(n_ref)]
mutation = rng.normal(0, self.r * 0.8, n_features).astype(np.float32)
candidate = np.clip(base + mutation, 0, 1)
```

The mutation magnitude `σ = r × 0.8 = 0.4` per dimension. In 77D, the expected L2 norm of the mutation vector is `σ√d = 0.4 × √77 ≈ 3.51`, normalized to `≈ 0.4`. This places candidates roughly at the self-boundary, which is good. However, `np.clip(base + mutation, 0, 1)` introduces **asymmetric bias** — candidates near the boundary of `[0,1]^d` get "squished" toward the edges, creating non-uniform detector density.

---

## 3. Detector Radius / Affinity Threshold 🔴 CRITICAL

**Code:** [nsa.py:97-100](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py#L97-L100)

```python
r_sq_thresh = (self.r ** 2) * n_features
```

This converts the user-facing radius `r` into a raw squared-distance threshold. The normalization logic is:

$$d_{\text{normalized}} = \frac{\|a - b\|_2}{\sqrt{d}} < r \iff \|a - b\|_2^2 < r^2 \cdot d$$

**This is mathematically correct** for the training side.

### 🔴 BUT: The radius is a **static hyperparameter** with no adaptive mechanism

The default `r = 0.5` is used for:
- **Training:** rejecting candidates within `r` of self (line 128)
- **Inference:** classifying flows further than `r` from self as anomalous (line 170)
- **Scoring:** both the antibody match radius and confidence calculation (lines 183, 188, 210)

> **[!CAUTION]**  
> **A single scalar `r` cannot simultaneously serve as:**
> 1. A negative-selection tolerance (how close is "too close to self")
> 2. A classification decision boundary (how far is "anomalous")
> 3. An antibody activation radius (how close to a detector triggers a match)
>
> These are three fundamentally different quantities. Using one value for all three is a **serious mathematical conflation**.

**Concrete failure mode:** If the self-manifold is non-convex (which network traffic absolutely is), a single hypersphere radius creates:
- False positives in sparse regions of the self-space (normal traffic that happens to be far from the 5,000 reference samples)
- False negatives near tight self-clusters (attacks that are close to one self-region but not truly self)

### Security Vulnerability (Acknowledged in README)

Your `analysis_security_audit.md` already identifies "Static radius evasion vectors" — an adversary who knows `r` can craft traffic at exactly `r - ε` distance from any self-reference point to evade detection deterministically.

---

## 4. Matching Function Correctness ✅

**Code:** [nsa.py:217-237](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py#L217-L237)

The squared-distance decomposition is correct:

$$\|a - b\|^2 = \|a\|^2 + \|b\|^2 - 2 \cdot a \cdot b$$

```python
x_sq = (batch * batch).sum(axis=1, keepdims=True)
dot = batch @ ref.T
sq = x_sq + ref_sq[np.newaxis, :] - 2.0 * dot
np.clip(sq, 0, None, out=sq)  # numerical safety
result[start:end] = np.sqrt(sq.min(axis=1)) / scale
```

**Verified:** 
- The `keepdims=True` broadcasting is correct
- The `np.clip(sq, 0, None)` handles floating-point underflow properly
- Division by `scale = √d` normalizes to the stated metric
- The chunking strategy (`PREDICT_CHUNK = 5_000`) prevents OOM

**Metric choice:** The implementation uses normalized Euclidean distance exclusively. No cosine similarity or Manhattan distance options exist. For MinMax-scaled features in `[0,1]^d`, Euclidean is a reasonable default, though cosine similarity would be more robust to feature magnitude variance.

---

## 5. Self Tolerance Handling ⚠️

**Code:** [nsa.py:86-94](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py#L86-L94)

```python
if n_self > SELF_REF_CAP:
    idx = rng.choice(n_self, size=SELF_REF_CAP, replace=False)
    ref = X_self[idx].astype(np.float32)
```

### Issue: `SELF_REF_CAP = 5,000` is a Lossy Approximation

The docstring claims: *"The self space is dense enough in the normalised feature space that a 5k subsample faithfully represents it."* This is stated without proof and is likely **false** for `d = 77`.

**Mathematical argument against faithfulness:**

By the coupon collector's problem and covering number theory, the number of samples needed to ε-cover a d-dimensional region scales as `O((1/ε)^d)`. For `d = 77` and even a coarse `ε = 0.1`, this is astronomically larger than 5,000.

**Practical impact:** The self-reference is a sparse point cloud in 77D. Many legitimate normal flows will be far from *any* reference point in the 5,000 sample, causing **false positives**. The distance `d(x, self_reference_)` overestimates `d(x, self_true)`.

### Self Tolerance in Inference

The `predict()` function at [nsa.py:170](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py#L170) has **zero tolerance**:

```python
return (dist_to_self > self.r).astype(int)
```

There is no soft margin or tolerance band. A sample at distance `r + 0.001` is labeled anomaly with the same confidence as one at `r + 10.0`. The `predict_with_scores` partially addresses this via the `base_scores` formula, but the binary label has no tolerance.

---

## 6. Detector Coverage Gaps 🔴

### Mathematical Proof of Inevitable Gaps

The non-self space `NS = [0,1]^d \setminus B(self, r)` has volume approximately:

$$V_{NS} \approx 1 - V_{self\_covered}$$

Each detector covers a hypersphere of radius `r` in the non-self space. The volume of a single hypersphere in `d = 77` dimensions with radius `r = 0.5` (normalized) is:

$$V_{\text{sphere}} = \frac{\pi^{d/2}}{\Gamma(d/2 + 1)} \cdot r^d$$

For `d = 77`, `r = 0.5`:

$$V_{\text{sphere}} \approx \frac{\pi^{38.5}}{\Gamma(39.5)} \cdot 0.5^{77}$$

This is an **astronomically small** number — effectively `≈ 10^{-24}` or smaller. With 500 detectors, the total covered volume is `≈ 500 × 10^{-24} ≈ 10^{-22}`.

> **The 500 detectors cover approximately 0.0000000000000000000001% of the non-self space.**

This is why the implementation **correctly** does NOT use detector matching for the primary classification. The `predict()` function uses distance-to-self, not distance-to-detector. The detectors only serve as confidence boosters in `predict_with_scores`.

**However, this means the detectors are essentially decorative for the binary classification decision.** The system is functionally a **1-class nearest-neighbor classifier**, not a Negative Selection Algorithm.

---

## 7. Detector Overlap Redundancy ⚠️

Given finding #6 (detectors cover negligible space), overlap is paradoxically both irrelevant and present:

- **Phase 1 detectors** (random): statistically unlikely to overlap in 77D
- **Phase 2 detectors** (boundary mutation): likely to cluster near self-boundary regions with multiple nearby self-samples

No deduplication or diversity enforcement exists. The antibody repertoire may contain clusters of near-identical detectors that waste budget.

**Recommendation:** Implement minimum inter-detector distance enforcement during generation:

```python
# Reject if too close to existing detector
if any(np.linalg.norm(candidate - d) < min_spacing for d in detectors):
    continue
```

---

## 8. False Positive / False Negative Tradeoff 🔴

The system provides **no mechanism** to independently control FP and FN rates.

| Parameter | Controls | Affects |
|-----------|----------|---------|
| `r` (radius) | Self-boundary size | Both FP and FN simultaneously |

- **Increasing `r`:** Larger self-tolerance → fewer FP, more FN (misses attacks near self)
- **Decreasing `r`:** Tighter self-tolerance → fewer FN, more FP (flags normal outliers)

> **There is no equivalent to a "threshold" parameter that can slide the operating point along an ROC curve without retraining.**

The `predict_with_scores` function returns continuous scores, so downstream code *could* apply a threshold different from `r`. But the binary `predict()` is hardcoded to `r`, and the API only exposes `predict()` for the primary label.

**Recommendation:** Add a `decision_threshold` parameter separate from `r`:

```python
def predict(self, X, threshold=None):
    t = threshold if threshold is not None else self.r
    return (self._min_dist_batch(X) > t).astype(int)
```

---

## 9. Detector Aging / Replacement 🔴 Missing

**There is no detector aging, expiration, or online learning mechanism.**

In biological Negative Selection:
- T-cells have a **finite lifespan**
- Continuously replaced by new candidates from the thymus
- The repertoire **adapts** to a changing self

In this implementation:
- Detectors are generated once during `fit()`
- They persist indefinitely via `joblib.dump`
- No mechanism for concept drift adaptation
- No online/incremental learning

**Impact:** If normal traffic patterns shift over time (e.g., new services, changed protocols), the self-model becomes stale. The system will generate increasing false positives on legitimate new traffic patterns without retraining.

---

## 10. Computational Complexity ✅ Well-Optimized

| Operation | Complexity | Notes |
|-----------|------------|-------|
| Training (fit) | `O(max_attempts × n_ref × d)` | With `n_ref = min(n_self, 5000)`, `d = 77` |
| Prediction (predict) | `O(n_test × n_ref × d / chunk)` | BLAS-accelerated matmul |
| Memory | `O(n_test × n_ref)` per chunk | Controlled by `PREDICT_CHUNK` |

The squared-distance decomposition avoids the `O(n × m × d)` explicit difference tensor. This is a legitimate and well-implemented optimization.

**Bottleneck analysis:**
- Training: `10,000 attempts × 5,000 refs × 77 features = 3.85 × 10^9` FLOPs → ~1-2 seconds on modern CPU
- Prediction per chunk: `5,000 × 5,000 × 77 ≈ 1.9 × 10^9` FLOPs → ~0.5-1 second per chunk
- Scaling is linear in test set size, which is acceptable

---

## 11. Training Data Contamination ⚠️

### Direct Contamination: Mitigated

The pipeline correctly filters training data:

```python
X_train_normal = X_train[y_train == 0]  # Only BENIGN
nsa.fit(X_train_normal)
```

### Indirect Contamination Risk: `SELF_REF_CAP` Sampling

If the training normal set contains **mislabeled attacks** (which CIC-IDS-2017 is known to have — some BENIGN flows exhibit attack-like characteristics), the 5,000-sample subsample may include contaminated points. These would expand the effective self-radius, creating blind spots for similar attacks.

### Scaler Contamination: Resolved

Per `analysis_ml_validation.md`, the scaler leakage has been fixed:

```python
# pipeline.py:118-119
preprocessor.fit(df_train_raw)  # Fitted on training split only
```

However, there's a subtle issue at [pipeline.py:151](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/pipeline.py#L151):

```python
iso.fit(X_train)  # Isolation Forest trains on ALL training data (normal + attack)
```

This is **correct by design** — Isolation Forest is semi-supervised. But it means the IF sees attack examples that the NSA never sees, giving IF a potential advantage in the comparison.

---

## 12. Feature Normalization Correctness ✅

**Code:** [preprocessor.py:127-128](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/preprocessor.py#L127-L128), [preprocessor.py:142-143](file:///c:/Users/kimeon/Desktop/ais-backend/app/core/preprocessor.py#L142-L143)

```python
self.scaler_ = MinMaxScaler()
self.scaler_.fit(X)
```

**Correct:** `MinMaxScaler` maps each feature to `[0, 1]` independently. This is the right choice for Euclidean-based NSA because:
- All features contribute equally to distance (no feature dominance)
- The normalized space `[0,1]^d` is the assumed domain for detector generation
- Phase 1 random candidates `rng.random(n_features)` are uniform in `[0,1]^d`, matching the scaled feature space

### Edge Case: Inference Values Outside Training Range

If inference-time features exceed the training min/max, `MinMaxScaler.transform()` will produce values outside `[0,1]`. The NSA doesn't clip these, so:
- A flow with a feature value of `2.0` (after scaling) would be further from self-reference
- This naturally flags extreme outliers as anomalies, which is desirable

No issue here.

---

## 13. Classification Decision Boundary ⚠️

The decision boundary is a **hypersphere of radius `r` around each self-reference point**, forming a union of overlapping hyperspheres:

$$\text{Self} = \bigcup_{i=1}^{n_{\text{ref}}} B(x_i^{\text{self}}, r)$$

Any point outside this union is classified as anomalous.

### Brittleness Issue

The boundary shape is determined entirely by the 5,000 reference samples and the scalar `r`. It cannot represent:

- **Non-convex self-regions** with concavities (the union of balls creates a convex-hull-like boundary)
- **Elongated/anisotropic clusters** (Euclidean distance is isotropic)
- **Multi-modal normal distributions** with varying density (each mode gets the same radius)

For CIC-IDS-2017, normal traffic likely contains multiple clusters (HTTP, DNS, SSH, background traffic, etc.) with different scales. A single `r` cannot accommodate all of them optimally.

### Comparison: Isolation Forest Doesn't Have This Limitation

Isolation Forest learns an adaptive, non-parametric boundary that naturally handles:
- Multi-modal distributions
- Non-convex regions
- Varying density

This is a **fundamental architectural disadvantage** of the NSA approach.

---

## 14. Biological NSA Fidelity ⚠️

| Biological Mechanism | Implementation Status |
|---|---|
| Self-set (thymus training) | ✅ Correctly uses only normal data |
| Negative Selection (delete self-reactive) | ✅ Candidates within `r` of self are rejected |
| Mature detector repertoire | ✅ Surviving detectors are stored |
| Clonal selection (detector amplification) | ❌ Missing — no mechanism to prioritize effective detectors |
| Somatic hypermutation | ⚠️ Partially implemented via Phase 2 boundary mutation |
| Detector lifespan / aging | ❌ Missing — detectors persist forever |
| Memory cells | ❌ Missing — no persistent memory of previously seen attacks |
| Danger signals / co-stimulation | ❌ Missing — no contextual activation |
| Affinity maturation | ❌ Missing — no iterative improvement of detector specificity |
| Immune network theory | ❌ Missing — detectors don't interact |

**Key deviation:** The `predict()` function bypasses the detector repertoire entirely, using distance-to-self instead. In biological NSA, detection happens when a **mature T-cell recognizes non-self** — the equivalent would be `distance-to-detector < r`. The current design is closer to a **1-class nearest-neighbor** with decorative detectors.

The `predict_with_scores` partially restores this with the antibody confidence boost, but the primary classification label ignores detectors.

---

## 15. Fairness Against Isolation Forest Baseline 🔴

### Structural Unfairness

| Dimension | NSA | Isolation Forest |
|---|---|---|
| Training data | Normal only (`y == 0`) | All training data (normal + attack) |
| Training paradigm | Unsupervised (no attack examples) | Semi-supervised (sees attack structure) |
| Hyperparameters | `r = 0.5` (default, not tuned) | `contamination = 0.05` (also default) |
| Decision mechanism | Fixed-radius hypersphere | Adaptive tree ensemble |
| Feature handling | Isotropic (all features equal weight) | Automatically selects discriminative features |

### Why This Comparison Disadvantages NSA

1. **Training data asymmetry:** IF sees attack examples during training; NSA does not. This gives IF an inherent advantage for detecting attacks it trained on.

2. **No hyperparameter tuning for either model:** Both use defaults. The NSA's `r = 0.5` is likely suboptimal for the specific dataset. IF's `contamination = 0.05` is also a guess. A fair comparison would cross-validate both.

3. **Metric choice:** F1-score treats FP and FN equally. In network security, FN (missed attacks) is typically much more costly than FP (false alarms). A cost-weighted metric would be more meaningful.

4. **`contamination` gives IF direct prior knowledge:** Setting `contamination = 0.05` tells IF that approximately 5% of training data is anomalous. The NSA has no such calibration parameter.

### What Would Be Fair

- Train both models on **only normal data** (IF with `novelty_detection=True` or `contamination='auto'`)
- Cross-validate `r` for NSA and `contamination` for IF
- Report ROC-AUC (threshold-independent) in addition to F1
- Use the same test set (already done ✅)

---

## Additional Findings

### A. Confidence Score Formula Has an Edge Case

**Code:** [nsa.py:183](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py#L183)

```python
base_scores = np.clip((dist_to_self - self.r) / max(1.0 - self.r, 1e-9), 0.0, 1.0)
```

This assumes `dist_to_self` has a maximum of `1.0`. But the normalized Euclidean distance in `[0,1]^d` has a theoretical maximum of `1.0` (since `max(||a-b||) / √d = √d/√d = 1`). So the formula is correct **if features stay in `[0,1]`**. However, as noted in §12, `MinMaxScaler` can produce values outside `[0,1]` at inference time, pushing `dist_to_self > 1.0`, which would clip to `1.0`. This is acceptable behavior.

### B. Antibody Match Logic Uses Same Radius

**Code:** [nsa.py:188](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py#L188)

```python
det_match = np.where(dist_to_det < self.r, 1.0 - (dist_to_det / self.r), 0.0)
```

The antibody activation radius equals the self-tolerance radius `r`. Biologically, these should differ — the activation threshold of a mature T-cell is independent of the thymus selection threshold.

### C. `_min_detector_distance` is an Alias Bug

**Code:** [nsa.py:257-258](file:///c:/Users/kimeon/Desktop/ais-backend/app/models/nsa.py#L257-L258)

```python
def _min_detector_distance(self, x: np.ndarray) -> tuple[float, bool]:
    return self._dist_to_self(x)
```

The method name suggests "distance to detector" but returns distance to **self**. This is a naming bug (leftover from refactoring). If any code calls this expecting detector distance, it will get wrong results.

### D. `datetime.utcnow()` is Deprecated

Multiple files use `datetime.utcnow()` which is deprecated since Python 3.12 in favor of `datetime.now(timezone.utc)`. Already partially migrated in `detection.py` but inconsistent elsewhere.

---

## Recommendations Priority Matrix

| Priority | Action | Impact |
|----------|--------|--------|
| 🔴 P0 | Decouple radius: separate `r_self` (self-tolerance), `r_detect` (classification threshold), `r_antibody` (detector activation) | Eliminates the fundamental mathematical conflation |
| 🔴 P0 | Add a `decision_threshold` parameter to `predict()` that can be tuned independently of training | Enables ROC curve exploration without retraining |
| 🟡 P1 | Replace Phase 1 uniform random generation with smarter sampling (e.g., k-means on self-boundary normals, or Latin hypercube) | Meaningful detector placement in 77D |
| 🟡 P1 | Add per-cluster adaptive radius (fit one `r` per k-means cluster of self) | Handles multi-modal normal traffic |
| 🟡 P1 | Make IF comparison fair: use `novelty_detection=True` or cross-validate both | Valid academic comparison |
| 🟢 P2 | Implement detector aging / online re-training | Concept drift resilience |
| 🟢 P2 | Add inter-detector spacing enforcement | Better coverage per detector budget |
| 🟢 P2 | Fix `_min_detector_distance` naming alias | Code clarity |

---

## Final Assessment

The implementation is **production-viable for an FYP demonstration** and shows strong engineering quality:
- The distance decomposition optimization is correct and efficient
- The leakage-free pipeline is properly structured
- The test suite validates core geometric properties
- The hybrid inference (self-gap + antibody boost) is a pragmatic design

**However, the system is mathematically closer to a 1-class nearest-neighbor with decorative antibodies than a true Negative Selection Algorithm.** The detectors play essentially no role in the binary classification decision. The fundamental limitation is the curse of dimensionality: in 77 dimensions, point-based methods cannot cover the non-self space, so the design correctly falls back to "distance from self" as the primary signal.

For the FYP report, I would recommend:
1. Being transparent about this limitation
2. Framing the antibodies as "forensic confidence boosters" (which they genuinely are in `predict_with_scores`)
3. Acknowledging that the comparison with Isolation Forest is structurally asymmetric
