# Denoising Autoencoder Ablation Result

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

## Comparison

| Representation | Latent Dim | Recall | FNR | FPR | Precision | F1 | TP | FN | FP | TN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| PCA + NSA | 1 | 5.24% | 94.76% | 5.48% | 28.48% | 8.85% | 262 | 4738 | 658 | 11342 |
| Denoising AE latent + NSA | 16 | 39.32% | 60.68% | 10.48% | 60.98% | 47.81% | 1966 | 3034 | 1258 | 10742 |

## Decision

- Winner: **PCA + NSA**
- Reason: Denoising AE did not produce a strong recall/F1 gain under the configured FPR tolerance.

## Notes

- Labels are used only after prediction for metrics.
- The denoising autoencoder is trained on BENIGN training rows only.
- This script does not modify production model artifacts.
