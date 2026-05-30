# DAE Tuning Grid Result

## Dataset

- File: `datasets\cicids2017\Portscan-Friday-no-metadata.parquet`
- total_rows: 119,522
- benign_rows_available: 117,566
- attack_rows_available: 1,956
- benign_rows_used: 60,000
- attack_rows_used: 1,956
- benign_train: 36,000
- benign_calibration: 12,000
- benign_test: 12,000
- eval_rows: 13,956

## Decision

- Winner: **Denoising AE latent + NSA**
- Reason: Best feasible DAE improved both Recall and F1 while staying within FPR <= 13.50%.
- Target FPR: 13.00%
- Accepted FPR limit: 13.50%

## Results

| Model | Config | Recall | FNR | FPR | Precision | F1 | TP | FN | FP | TN |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| PCA + NSA | PCA | 14.11% | 85.89% | 8.44% | 21.41% | 17.01% | 276 | 1680 | 1013 | 10987 |
| Denoising AE latent + NSA | dim=8, noise=0.05 | 70.30% | 29.70% | 12.32% | 48.19% | 57.18% | 1375 | 581 | 1478 | 10522 |
| Denoising AE latent + NSA | dim=24, noise=0.03 | 57.77% | 42.23% | 12.70% | 42.58% | 49.02% | 1130 | 826 | 1524 | 10476 |
| Denoising AE latent + NSA | dim=24, noise=0.05 | 53.78% | 46.22% | 12.52% | 41.19% | 46.65% | 1052 | 904 | 1502 | 10498 |
| Denoising AE latent + NSA | dim=8, noise=0.08 | 52.86% | 47.14% | 12.15% | 41.49% | 46.49% | 1034 | 922 | 1458 | 10542 |
| Denoising AE latent + NSA | dim=8, noise=0.03 | 52.76% | 47.24% | 12.30% | 41.15% | 46.24% | 1032 | 924 | 1476 | 10524 |
| Denoising AE latent + NSA | dim=16, noise=0.08 | 36.76% | 63.24% | 12.47% | 32.46% | 34.48% | 719 | 1237 | 1496 | 10504 |
| Denoising AE latent + NSA | dim=16, noise=0.05 | 33.84% | 66.16% | 12.31% | 30.95% | 32.33% | 662 | 1294 | 1477 | 10523 |
| Denoising AE latent + NSA | dim=16, noise=0.03 | 33.84% | 66.16% | 12.64% | 30.38% | 32.02% | 662 | 1294 | 1517 | 10483 |
| Denoising AE latent + NSA | dim=24, noise=0.08 | 33.23% | 66.77% | 12.22% | 30.72% | 31.93% | 650 | 1306 | 1466 | 10534 |

## Notes

- Autoencoder training uses BENIGN training rows only.
- Labels are used only after prediction for metrics.
- This is an offline experiment and does not update deployed artifacts.
