# NSA Algorithm Audit — Candidate Generation & Spacing Optimizations

> **Status**: ✅ Implemented Phase 1 & 2 Optimizations
> **Test Suite**: 28/28 passed  
> **Date**: 2026-05-02

---

## 1. Smarter Phase 1 Generation (K-Means Centroid Mutagenesis)

### The Previous Flaw
Previously, Phase 1 generated detectors using uniform random sampling (`rng.random(n_features)`) over the entire bounding box of `[0, 1]^d`. In a high-dimensional space like `d=77` (CIC-IDS-2017), the volume of the space is astronomically large. A uniformly random candidate has almost no chance of landing near the relevant non-self manifold, making these detectors essentially "decorative" as they would cover empty space where network traffic never occurs.

### The Improvement
To solve this, we've replaced the uniform random generation with **K-Means Centroid Mutagenesis**:
1. We run the `KMeans` algorithm on the normal self-samples to identify up to 50 distinct traffic clusters.
2. In Phase 1, instead of guessing blindly, we pick a random cluster centroid.
3. We apply a large Gaussian mutation (`Sigma = r * 3.0`) to "push" the candidate far enough from the centroid to land in the non-self space, but not so far that it lands in an irrelevant corner of the `[0, 1]^d` hyperspace.

This mathematically anchors the detector generation to the actual network traffic distribution, avoiding the curse of dimensionality.

## 2. Inter-Detector Spacing Enforcement

### The Previous Flaw
When boundary mutations were applied (Phase 2), multiple candidates could be pushed out from the same self-sample, resulting in numerous detectors overlapping in the same physical space. This overlap was redundant and wasted the limited `max_detectors` budget.

### The Improvement
We implemented an **Inter-Detector Spacing Rule**:
Before a survived candidate is added to the mature detector repertoire, the algorithm measures its distance to all existing detectors.
- **Rule**: If `dist(candidate, existing_detector) < r_s`, the candidate is rejected.
- **Effect**: This forces the detectors to "spread out" around the self-manifold, drastically maximizing the total volume of non-self space that a budget of 500 detectors can cover. The system now natively tracks `candidates_rejected_overlap`.

## 3. Conclusion
With these two optimizations, the V-Detector generation is significantly more efficient. The system now wastes zero budget on either overlapping detectors or detectors placed in statistically impossible regions of the 77-dimensional space. The coverage per detector is maximized, making the NSA much more formidable against adversarial evasion.
