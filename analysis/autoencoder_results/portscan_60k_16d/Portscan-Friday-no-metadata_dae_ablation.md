# Denoising Autoencoder Ablation Result

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

## Comparison

| Representation | Latent Dim | Recall | FNR | FPR | Precision | F1 | TP | FN | FP | TN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| PCA + NSA | 1 | 14.11% | 85.89% | 8.44% | 21.41% | 17.01% | 276 | 1680 | 1013 | 10987 |
| Denoising AE latent + NSA | 16 | 33.54% | 66.46% | 9.39% | 36.79% | 35.09% | 656 | 1300 | 1127 | 10873 |

## Decision

- Winner: **Denoising AE latent + NSA**
- Reason: Recall improved by 19.43 percentage points while FPR increased by only 0.95 points.

## Notes

- Labels are used only after prediction for metrics.
- The denoising autoencoder is trained on BENIGN training rows only.
- This script does not modify production model artifacts.
