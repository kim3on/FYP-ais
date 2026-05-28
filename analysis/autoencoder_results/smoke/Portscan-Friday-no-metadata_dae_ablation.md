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
| Denoising AE latent + NSA | 1 | 5.73% | 94.27% | 8.13% | 25.63% | 9.36% | 112 | 1844 | 325 | 3675 |

## Decision

- Winner: **PCA + NSA**
- Reason: Denoising AE did not produce a strong recall/F1 gain under the configured FPR tolerance.

## Notes

- Labels are used only after prediction for metrics.
- The denoising autoencoder is trained on BENIGN training rows only.
- This script does not modify production model artifacts.
