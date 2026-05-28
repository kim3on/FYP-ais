# Denoising Autoencoder Ablation Result

## Dataset

- File: `datasets\cicids2017\Portscan-Friday-no-metadata.parquet`
- total_rows: 119,522
- benign_rows_available: 117,566
- attack_rows_available: 1,956
- benign_rows_used: 20,000
- attack_rows_used: 1,956
- benign_train: 12,000
- benign_calibration: 4,000
- benign_test: 4,000
- eval_rows: 5,956

## Comparison

| Representation | Latent Dim | Recall | FNR | FPR | Precision | F1 | TP | FN | FP | TN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| PCA + NSA | 1 | 15.18% | 84.82% | 8.13% | 47.75% | 23.04% | 297 | 1659 | 325 | 3675 |
| Denoising AE latent + NSA | 16 | 49.18% | 50.82% | 9.10% | 72.55% | 58.62% | 962 | 994 | 364 | 3636 |

## Decision

- Winner: **Denoising AE latent + NSA**
- Reason: Recall improved by 34.00 percentage points while FPR increased by only 0.97 points.

## Notes

- Labels are used only after prediction for metrics.
- The denoising autoencoder is trained on BENIGN training rows only.
- This script does not modify production model artifacts.
