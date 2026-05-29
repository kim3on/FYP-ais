# Denoising Autoencoder Ablation Result

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

## Comparison

| Representation | Latent Dim | Recall | FNR | FPR | Precision | F1 | TP | FN | FP | TN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| PCA + NSA | 1 | 40.90% | 59.10% | 8.84% | 65.84% | 50.46% | 2045 | 2955 | 1061 | 10939 |
| Denoising AE latent + NSA | 16 | 9.62% | 90.38% | 9.58% | 29.51% | 14.51% | 481 | 4519 | 1149 | 10851 |

## Decision

- Winner: **PCA + NSA**
- Reason: Denoising AE did not produce a strong recall/F1 gain under the configured FPR tolerance.

## Notes

- Labels are used only after prediction for metrics.
- The denoising autoencoder is trained on BENIGN training rows only.
- This script does not modify production model artifacts.
