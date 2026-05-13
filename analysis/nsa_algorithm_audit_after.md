# NSA Algorithm Audit — V-Detector Implementation

> **Status**: ✅ All 4 critical issues resolved  
> **Test Suite**: 28/28 passed  
> **Date**: 2026-05-02

> **May 2026 update:** The current implementation builds on this V-Detector rewrite with `RobustScaler + PCA(whiten=True)`, dynamic PCA-space `r`/`r_s` calibration, and detector generation without `[0,1]` clipping. The table below reflects the first V-Detector fix pass; use README/DATAFLOW for current runtime defaults.

---

## Summary of Changes

### Critical Issues Fixed

| # | Issue | Before | After |
|---|-------|--------|-------|
| 1 | **Radius conflation** | Single `r` served as self-tolerance, classification threshold, AND detector radius | `r_s` (training tolerance) decoupled from `r` (self-gap threshold) + variable per-detector radii |
| 2 | **Detectors were decorative** | Classification used distance-to-self only; detectors were confidence boosters | V-Detector matching is the **PRIMARY** classification mechanism |
| 3 | **No detector aging** | Detectors persisted forever | Idle-batch tracking + `refresh()` method for stale detector replacement |
| 4 | **Fixed detector radius** | All detectors had identical radius `r` | Each detector has `radius = dist_to_nearest_self − r_s` (V-Detector algorithm) |

### Architecture: Before vs After

```
BEFORE (1-class nearest-neighbor pretending to be NSA):
  predict(x) = dist_to_self(x) > r  →  anomaly
  detectors  = used only for confidence scoring (decorative)

AFTER (True V-Detector NSA):
  predict(x) = matches_any_vdetector(x)  OR  dist_to_self(x) > r  →  anomaly
               ─────────────────────────     ────────────────────
               PRIMARY (adaptive immune)     FALLBACK (innate immune)
```

## Files Modified

| File | Change |
|------|--------|
| `app/models/nsa.py` | Complete rewrite — V-Detector algorithm, variable radii, detector-primary classification, aging infrastructure |
| `app/schemas.py` | Added `r_s` parameter to `TrainConfig` |
| `app/core/pipeline.py` | Passes `r_s` through to NSA constructor |
| `app/routers/training.py` | Exposes `r_s` in training API endpoint |
| `test_backend.py` | 6 new/updated tests validating V-Detector properties |

## Parameter Guide

| Parameter | Default | Role | Biological Analog |
|-----------|---------|------|-------------------|
| `r` | Auto-calibrated by default | Self-gap detection threshold — triggers fallback when sample is far from all self | Innate immune response threshold |
| `r_s` | Auto-calibrated by default | Self-tolerance for negative selection — candidates within `r_s` of self are deleted | Thymus selection stringency |
| `max_detectors` | 1,000 in the API endpoint | Maximum mature V-detectors | T-cell repertoire size |
| `max_attempts` | 30,000 in the API endpoint | Candidate generation budget | Thymus throughput |

## New Test Coverage

| Test | What it validates |
|------|-------------------|
| `V-Detector fits with variable radii` | Each detector has a positive variable radius |
| `No V-detector sphere overlaps self` | Core NSA invariant — detectors don't react to self |
| `Radii are genuinely variable` | `std(radii) > 0.01` — not fixed-radius |
| `Detectors catch attacks (10D)` | V-detectors function as primary mechanism (100% catch rate in 10D) |
| `Zero false positives` | Self samples never flagged |
| `F1/recall/precision ≥ 0.95` | End-to-end accuracy on synthetic data |

## Known Limitation: Curse of Dimensionality

In 77D (CIC-IDS-2017), 500 V-detectors cannot cover the full non-self space. The self-gap fallback is essential for completeness. In the FYP report, frame this as:

> *"The system implements a hybrid V-Detector NSA where mature detectors provide specific pattern recognition (adaptive immune response) and the self-gap mechanism provides general novelty detection (innate immune response). This mirrors the biological immune system's layered defense architecture."*

## Remaining Recommendations (Non-Critical)

1. **Hyperparameter tuning**: Use cross-validation to optimize `r` and `r_s` for the CIC-IDS-2017 dataset
2. **IF comparison fairness**: Consider adding `IsolationForest(novelty=True)` trained on normal-only data as a third baseline
3. **Decision threshold**: Expose a `sensitivity` slider in the API that maps to the anomaly score cutoff
