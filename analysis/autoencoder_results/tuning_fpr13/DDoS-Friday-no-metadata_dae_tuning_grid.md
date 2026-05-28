# DAE Tuning Grid Result

## Dataset

- File: `datasets\cicids2017\DDoS-Friday-no-metadata.parquet`
- total_rows: 221,264
- benign_rows_available: 93,250
- attack_rows_available: 128,014
- benign_rows_used: 60,000
- attack_rows_used: 5,000
- benign_train: 36,000
- benign_calibration: 12,000
- benign_test: 12,000
- eval_rows: 17,000

## Decision

- Winner: **Denoising AE latent + NSA**
- Reason: Best feasible DAE improved both Recall and F1 while staying within FPR <= 13.50%.
- Target FPR: 13.00%
- Accepted FPR limit: 13.50%

## Results

| Model | Config | Recall | FNR | FPR | Precision | F1 | TP | FN | FP | TN |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| PCA + NSA | PCA | 5.24% | 94.76% | 5.48% | 28.48% | 8.85% | 262 | 4738 | 658 | 11342 |
| Denoising AE latent + NSA | dim=8, noise=0.05 | 66.78% | 33.22% | 12.93% | 68.28% | 67.52% | 3339 | 1661 | 1551 | 10449 |
| Denoising AE latent + NSA | dim=24, noise=0.05 | 44.52% | 55.48% | 13.32% | 58.21% | 50.45% | 2226 | 2774 | 1598 | 10402 |
| Denoising AE latent + NSA | dim=16, noise=0.08 | 40.52% | 59.48% | 13.21% | 56.11% | 47.06% | 2026 | 2974 | 1585 | 10415 |
| Denoising AE latent + NSA | dim=16, noise=0.05 | 39.70% | 60.30% | 13.03% | 55.95% | 46.44% | 1985 | 3015 | 1563 | 10437 |
| Denoising AE latent + NSA | dim=24, noise=0.03 | 38.84% | 61.16% | 12.83% | 55.79% | 45.80% | 1942 | 3058 | 1539 | 10461 |
| Denoising AE latent + NSA | dim=8, noise=0.03 | 38.52% | 61.48% | 13.43% | 54.45% | 45.12% | 1926 | 3074 | 1611 | 10389 |
| Denoising AE latent + NSA | dim=8, noise=0.08 | 38.00% | 62.00% | 12.86% | 55.18% | 45.01% | 1900 | 3100 | 1543 | 10457 |
| Denoising AE latent + NSA | dim=16, noise=0.03 | 40.32% | 59.68% | 13.69% | 55.10% | 46.56% | 2016 | 2984 | 1643 | 10357 |
| Denoising AE latent + NSA | dim=24, noise=0.08 | 39.66% | 60.34% | 13.62% | 54.82% | 46.03% | 1983 | 3017 | 1634 | 10366 |

## Notes

- Autoencoder training uses BENIGN training rows only.
- Labels are used only after prediction for metrics.
- This is an offline experiment and does not update deployed artifacts.
