Yes, your `.md` is directionally good. I’d **combine it** with my fix, because they solve different parts of the same PCA problem.

**Best Combined Strategy**
1. **Keep PCA**
   PCA is valid for CIC-IDS-2017 because 77D distance geometry is noisy and sparse.

2. **Stop assuming `[0,1]` after PCA**
   This was my main fix. In `app/models/nsa.py`, detector generation should not blindly do:
   ```python
   np.clip(candidate, 0, 1)
   ```
   after PCA. PCA space can be negative and unbounded.

3. **Use dynamic `r`**
   Your markdown’s percentile-based `r` is probably the most important improvement. Instead of hardcoded `r=0.3`, compute it from benign PCA-space distances. I would use nearest-neighbor self distances, not full pairwise distances if the reference set is large.

   Recommended:
   - compute distance to nearest other benign sample
   - set `r = 99th` or `99.5th` percentile
   - maybe expose percentile as config

4. **Use dynamic `r_s`**
   Also good. Set `r_s` from local benign density. For example:
   - `r_s = 50th` or `75th` percentile of benign nearest-neighbor distances
   - keep it smaller than `r`
   - enforce minimum/maximum bounds

5. **Replace MinMaxScaler with RobustScaler before PCA**
   The implemented pipeline now uses:
   ```text
   RobustScaler → PCA(whiten=True) → NSA
   ```
   For distance-based AIS, `RobustScaler + PCA(whiten=True)` is cleaner because Euclidean distance becomes more balanced across PCA components.

**My recommendation**
Use this architecture:

```text
Raw CIC features
→ clean inf/NaN/extremes
→ RobustScaler
→ PCA(whiten=True)
→ NSA with learned PCA-space bounds
→ dynamic r and r_s from benign distance distribution
```

 for **threshold calibration** and fix for **correct PCA-space detector geometry**. 
 Together, they are much stronger than either one alone.
