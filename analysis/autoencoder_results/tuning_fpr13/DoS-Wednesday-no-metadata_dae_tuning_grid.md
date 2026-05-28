# DAE Tuning Grid Result

## Dataset

- File: `datasets\cicids2017\DoS-Wednesday-no-metadata.parquet`
- total_rows: 584,991
- benign_rows_available: 391,235
- attack_rows_available: 193,756
- benign_rows_used: 60,000
- attack_rows_used: 5,000
- benign_train: 36,000
- benign_calibration: 12,000
- benign_test: 12,000
- eval_rows: 17,000

## Decision

- Winner: **PCA + NSA**
- Reason: Best feasible DAE did not beat PCA on both Recall and F1.
- Target FPR: 13.00%
- Accepted FPR limit: 13.50%

## Results

| Model | Config | Recall | FNR | FPR | Precision | F1 | TP | FN | FP | TN |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| PCA + NSA | PCA | 40.90% | 59.10% | 8.84% | 65.84% | 50.46% | 2045 | 2955 | 1061 | 10939 |
| Denoising AE latent + NSA | dim=16, noise=0.03 | 18.24% | 81.76% | 13.14% | 36.64% | 24.36% | 912 | 4088 | 1577 | 10423 |
| Denoising AE latent + NSA | dim=16, noise=0.08 | 17.04% | 82.96% | 12.73% | 35.81% | 23.09% | 852 | 4148 | 1527 | 10473 |
| Denoising AE latent + NSA | dim=8, noise=0.08 | 13.18% | 86.82% | 12.24% | 30.97% | 18.49% | 659 | 4341 | 1469 | 10531 |
| Denoising AE latent + NSA | dim=24, noise=0.08 | 12.24% | 87.76% | 12.74% | 28.58% | 17.14% | 612 | 4388 | 1529 | 10471 |
| Denoising AE latent + NSA | dim=24, noise=0.03 | 12.10% | 87.90% | 12.72% | 28.39% | 16.97% | 605 | 4395 | 1526 | 10474 |
| Denoising AE latent + NSA | dim=16, noise=0.05 | 10.28% | 89.72% | 12.38% | 25.70% | 14.69% | 514 | 4486 | 1486 | 10514 |
| Denoising AE latent + NSA | dim=24, noise=0.05 | 9.70% | 90.30% | 12.50% | 24.43% | 13.89% | 485 | 4515 | 1500 | 10500 |
| Denoising AE latent + NSA | dim=8, noise=0.03 | 7.70% | 92.30% | 12.25% | 20.75% | 11.23% | 385 | 4615 | 1470 | 10530 |
| Denoising AE latent + NSA | dim=8, noise=0.05 | 6.88% | 93.12% | 12.93% | 18.15% | 9.98% | 344 | 4656 | 1551 | 10449 |

## Notes

- Autoencoder training uses BENIGN training rows only.
- Labels are used only after prediction for metrics.
- This is an offline experiment and does not update deployed artifacts.
