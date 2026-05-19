# AIS-Detect Data Flow

> Project: Web-Based Network Anomaly Detection using Artificial Immune Systems  
> Backend: FastAPI, Python, SQLite, Scapy  
> Frontend: React + Vite  
> Main dataset: CICIDS2017 flow records  
> Batch benchmark dataset: NSL-KDD  
> Main model: Artificial Immune System using Negative Selection Algorithm / V-Detector NSA  
> Baseline model: Isolation Forest  

---

## 1. Architecture Summary

AIS-Detect is a web-based intrusion detection prototype. It has three main workflows:

| Workflow | Purpose |
|---|---|
| Training | Learn the profile of benign/self traffic |
| Batch Detection | Analyse uploaded CICIDS2017-style flow files |
| Live Capture | Convert live packets into CICIDS2017-style flow features and score them |

The current architecture is strict unsupervised detection:

- NSA trains only on BENIGN/self traffic.
- RobustScaler and PCA are fitted only on BENIGN training rows.
- Self-boundary statistics are fitted only on BENIGN training rows.
- Final anomaly threshold is calibrated only from BENIGN calibration rows.
- Labels are not used to tune NSA, PCA, scaler, self-boundary, score weights, or thresholds.
- Labels are used only after detection for verification metrics.

The main output is binary:

```text
Normal vs Anomaly
```

Attack family guessing is a second layer for display only. It does not decide whether a row is anomalous.

Dataset profiles are separated so incompatible feature schemas are not mixed:

| Profile | Use | Live capture | Artifact folder |
|---|---|---|---|
| `cicids2017` | Main CICFlowMeter-style IDS workflow | Yes | `app/artefacts/cicids2017/` |
| `nsl_kdd` | Offline batch benchmark | No | `app/artefacts/nsl_kdd/` |

---

## 2. Startup Flow

```text
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

1. FastAPI starts and registers routers.
2. SQLite tables are created if missing.
3. Default users are seeded if the user table is empty.
4. Existing firewall blocks are loaded into memory.
5. If `app/static_react/` exists, FastAPI serves the built React dashboard.

Main routers:

| Router | Responsibility |
|---|---|
| `auth` | Login, JWT authentication |
| `training` | Dataset upload, model training, training logs |
| `detection` | Batch detection on uploaded files |
| `capture` | Live packet capture and WebSocket updates |
| `alerts` | Alert list, false-positive marking, CSV export |
| `dashboard` | Status and dashboard summary |
| `firewall` | Windows Firewall block/unblock |

---

## 3. Authentication Flow

```text
Browser
  -> POST /api/auth/login
  <- JWT token + role
```

- Passwords are checked against bcrypt hashes in SQLite.
- The frontend stores the JWT in React context.
- HTTP calls send `Authorization: Bearer <token>`.
- WebSocket clients connect using `/ws/live?token=<jwt>`.
- Invalid WebSocket tokens are rejected before the socket is accepted.

---

## 4. Training Data Flow

Training is the main immune-system learning phase. It teaches the system what normal/self traffic looks like.

### 4.1 Upload

```text
Browser
  -> POST /api/train
  <- "Training started"
```

The backend:

1. Reads uploaded CSV or Parquet bytes.
2. Sets system status to `learning`.
3. Starts `TrainingPipeline.run()` as a background task.
4. Streams progress through `GET /api/train/logs`.

### 4.2 Benign-Only Split

```text
Uploaded dataset file
    |
    v
Load CSV / Parquet
    |
    v
Find Label column
    |
    v
Map Label:
    BENIGN -> self / normal
    non-BENIGN -> attack label for reporting only
    |
    v
Select dataset profile:
    cicids2017 -> CICIDSPreprocessor
    nsl_kdd    -> NSLKDDPreprocessor
    |
    v
Keep only BENIGN/normal rows for fitting and calibration
    |
    v
Split BENIGN rows:
    train       -> fit scaler, PCA, NSA, self-boundary
    calibration -> calibrate component scales and final threshold
    test        -> benign holdout FPR / self-intrusion check
```

Attack rows are not used for model fitting or threshold selection. If the uploaded training file contains attack rows, they are ignored for learning and may only be counted for reporting.

### 4.3 Preprocessing

Files:

- `app/core/preprocessor.py` for CICIDS2017.
- `app/core/nsl_kdd_preprocessor.py` for NSL-KDD.

```text
BENIGN train rows
    |
    v
Clean CICIDS2017 columns
    |
    v
Drop metadata columns
    |
    v
Replace inf / NaN
    |
    v
Clip extreme values
    |
    v
Fit RobustScaler on BENIGN train only
    |
    v
Fit PCA(whiten=True) on BENIGN train only
    |
    v
Transform train / calibration / test using fitted scaler + PCA
```

Important rule:

```text
No calibration/test/detection rows are used to fit RobustScaler or PCA.
```

This prevents data leakage.

### 4.4 NSA V-Detector Training

File: `app/models/nsa.py`

```text
BENIGN train rows in PCA space
    |
    v
Build self-reference set
    |
    v
Estimate benign self-distance statistics
    |
    v
Generate detector candidates around self-space boundaries
    |
    v
Reject candidate if it reacts to self
    |
    v
Accept mature V-detector if it is outside self tolerance
    |
    v
Store detector center + variable radius
```

NSA detector generation happens in PCA-whitened feature space. The model does not assume `[0, 1]` bounds after PCA.

NSA produces component scores:

| Score | Meaning |
|---|---|
| Distance/self-gap score | How far the sample is from known self traffic |
| Detector-depth score | How strongly the sample falls inside mature detector regions |
| k-nearest-self density score | Whether the sample is in sparse self-space |

These are continuous scores. They are not final labels by themselves.

### 4.5 Self-Boundary Training

File: `app/models/self_boundary.py`

AIS-Detect now trains two benign-only Self-Boundary models:

| Model | Space | Purpose |
|---|---|---|
| Raw Self-Boundary | Cleaned raw feature space | Human-readable feature evidence |
| PCA Self-Boundary | PCA-whitened feature space | Final fused AIS anomaly scoring |

```text
BENIGN train rows in raw feature space
    |
    v
Learn empirical quantile fences per feature
    |
    v
Measure how often benign rows violate each feature boundary
    |
    v
Give rarer benign violations higher weight
    |
    v
Produce continuous weighted violation score for evidence

BENIGN train rows in PCA space
    |
    v
Learn empirical quantile fences per PCA component
    |
    v
Produce PCA-space Self-Boundary score for fusion
```

This is used as an AIS autoimmunity check: the model should not react too often to benign/self traffic.

### 4.6 Benign-Calibrated Score Fusion

The final AIS anomaly score is a weighted fusion of NSA and PCA Self-Boundary scores.

```text
BENIGN calibration rows
    |
    v
NSA component scores
    + PCA self-boundary weighted score
    |
    v
Scale each component using BENIGN calibration quantiles only
    |
    v
Weighted fusion score
    |
    v
Set final threshold from benign score quantile
    |
    v
Target FPR = 5%
```

Current score-fusion idea:

```text
fused_score =
    weighted NSA distance score
  + weighted NSA density score
  + weighted NSA detector-depth score
  + weighted PCA self-boundary score
```

The saved threshold is unsupervised because it is selected only from BENIGN calibration scores.

### 4.7 Training Outputs

Training saves:

| Artefact | Purpose |
|---|---|
| `app/artefacts/<dataset>/nsa_model.pkl` | NSA detectors, self-reference set, fusion calibration |
| `app/artefacts/<dataset>/self_boundary.pkl` | Raw feature boundary statistics and weighted evidence calibration |
| `app/artefacts/<dataset>/pca_self_boundary.pkl` | PCA-space Self-Boundary model used for fused scoring |
| `app/artefacts/<dataset>/iso_model.pkl` | Isolation Forest baseline |
| `app/artefacts/<dataset>/preprocessor.pkl` | RobustScaler, PCA, feature schema |
| `app/artefacts/<dataset>/last_train_result.json` | Dashboard training summary |

Training result JSON includes:

| Field | Meaning |
|---|---|
| `validation_mode` | Strict unsupervised benign calibration mode |
| `target_fpr` | Desired benign false-positive rate |
| `observed_benign_fpr` | FPR observed on benign calibration/holdout rows |
| `self_intrusion_rate` | Percentage of benign validation rows flagged as anomaly |
| `normal_pass_rate` | Percentage of benign rows accepted as normal |
| `silhouette_score` | Optional separation score for predicted normal/anomaly groups |
| `fusion_calibration` | Component scales, weights, threshold, score mode |

Training does not report precision, recall, or F1 as training-success metrics because benign-only training has no attack target.

---

## 5. Batch Detection Flow

File: `app/core/detection.py`

```text
Browser
  -> POST /api/detect
  <- "Detection started"
```

```text
Uploaded detection file
    |
    v
Load saved preprocessor, NSA, raw Self-Boundary, PCA Self-Boundary, optional IsoForest
    |
    v
Transform rows using fitted RobustScaler + PCA
    |
    v
Calculate self-boundary weighted scores from raw features
    |
    v
Calculate PCA self-boundary weighted scores from PCA features
    |
    v
Calculate NSA component scores from PCA features
    |
    v
Apply saved benign-calibrated fusion score
    |
    v
fused_score > threshold -> Anomaly
fused_score <= threshold -> Normal
```

The detection file may contain labels, but labels are not read until after predictions are complete.

### 5.1 Layer 1: Unsupervised Binary Detection

Layer 1 decides only:

```text
Normal or Anomaly
```

It uses:

- NSA V-detector evidence in PCA space.
- NSA self-gap/density evidence in PCA space.
- PCA Self-Boundary weighted violation evidence for scoring.
- Raw Self-Boundary evidence for explanation.
- Saved fusion threshold from benign calibration.

### 5.2 Layer 2: Attack Family Guessing

Layer 2 runs only on rows already flagged as anomalies.

It guesses a likely family using flow-feature heuristics:

```text
DDoS, DoS, Brute Force, PortScan, Botnet, Web Attack, Infiltration,
or Zero-Day Candidate
```

This layer is optional display logic. It does not change TP, FP, FN, TN. A wrong family guess is not counted as a false negative because the main detector is anomaly-based.

### 5.3 Layer 3: Post-Run Labelled Verification

If the uploaded detection file has a label column, the backend computes verification metrics after prediction:

| Metric | Meaning |
|---|---|
| TP | Attack rows flagged as anomaly |
| TN | Benign rows passed as normal |
| FP | Benign rows flagged as anomaly |
| FN | Attack rows missed as normal |
| Recall / TPR | Percentage of attacks caught |
| FNR | Percentage of attacks missed |
| FPR | Percentage of benign rows incorrectly alerted |
| Precision | Percentage of alerts that were true attacks |
| F1-score | Balance of precision and recall |
| Accuracy | Report-only; not the main IDS metric |

These metrics are verification only. They are not fed back into the model.

### 5.4 Threshold Trade-Off Analysis

For labelled detection files, the system can also evaluate different score thresholds:

```text
threshold -> recall, FNR, FPR, precision, F1
```

This table is report-only. It helps explain the recall/FPR trade-off, but it does not automatically alter the saved unsupervised model threshold.

---

## 6. Live Capture Flow

Live capture uses the same trained artefacts but receives packet-derived flow features instead of uploaded dataset rows.

```text
Network interface
    |
    v
Scapy sniffer thread
    |
    v
FlowAggregator groups packets by 5-tuple
    |
    v
FlowFeatureExtractor builds CICIDS2017-style features
    |
    v
DetectionEngine.detect_sample()
    |
    v
Normal / Anomaly decision
    |
    v
Update dashboard counters, chart, SQLite, WebSocket clients
```

Live capture has no ground-truth labels. Therefore live mode can show:

- total flows
- normal count
- anomaly count
- anomaly rate
- severity counts
- alert records

Live mode cannot honestly show recall, precision, F1, or FNR because there are no true labels.

---

## 7. Frontend Data Flow

The React dashboard calls the backend API through `frontend/src/api/index.js`.

Main pages:

| Page | Data |
|---|---|
| Dashboard | System status, live counters, live traffic graph |
| Train & Detect | Training upload, detection upload, metrics, logs |
| Alerts | Alert table, filtering, false-positive marking |
| Settings | Model/runtime settings, data management, system information |

Training page polling:

```text
POST /api/train
GET /api/train/logs
GET /api/train/result
```

Detection page polling:

```text
POST /api/detect
GET /api/detect/logs
GET /api/detect/result
```

Live dashboard:

```text
POST /api/capture/start
WS /ws/live?token=<jwt>
POST /api/capture/stop
```

---

## 8. Shared State

File: `app/state.py`

The backend keeps runtime state in a shared in-memory dictionary.

Important fields:

| State field | Meaning |
|---|---|
| `status` | `idle`, `learning`, `active`, or `error` |
| `training_logs` | Training log lines streamed to frontend |
| `detect_logs` | Detection log lines streamed to frontend |
| `alerts` | In-memory alert list |
| `active_model` | Current model selection |
| `active_dataset_type` | Current dataset profile, such as `cicids2017` or `nsl_kdd` |
| `capture_active` | Whether live capture is running |
| `chart_normal` | Live traffic normal-flow ring buffer |
| `chart_anomaly` | Live traffic anomaly-flow ring buffer |
| `last_train_result` | Last training output |
| `last_detect_result` | Last detection output |

SQLite remains the persistent store for users, alerts, blocked IPs, and raw flows. Runtime settings persist the active model and active dataset profile in `app/artefacts/runtime_settings.json`.

---

## 9. Database Flow

SQLite tables:

| Table | Purpose |
|---|---|
| `users` | Login users and bcrypt password hashes |
| `alerts` | Persisted anomaly alerts |
| `blocked_ips` | Firewall block records |
| `raw_flows` | Lightweight live flow log |

Alert flow:

```text
DetectionEngine creates AlertRecord
    |
    +-> append to in-memory state
    |
    +-> write to SQLite AlertDB
    |
    +-> frontend fetches through /api/alerts
```

---

## 10. Current End-to-End View

```text
React Browser
    |
    | HTTP / WebSocket
    v
FastAPI Backend
    |
    +-- Auth router
    |
    +-- Training router
    |       |
    |       v
    |   TrainingPipeline
    |       |
    |       +-- CICIDSPreprocessor
    |       |       fit RobustScaler + PCA on BENIGN train only
    |       |
    |       +-- NSLKDDPreprocessor
    |       |       batch-only benchmark preprocessing when dataset_type=nsl_kdd
    |       |
    |       +-- NegativeSelectionDetector
    |       |       generate V-detectors in PCA space
    |       |
    |       +-- SelfBoundaryDetector
    |       |       learn raw-feature evidence boundary
    |       |
    |       +-- PCA SelfBoundaryDetector
    |       |       learn PCA-space boundary for fused scoring
    |       |
    |       +-- Score fusion calibration
    |               calibrate threshold on BENIGN calibration only
    |
    +-- Detection router
    |       |
    |       v
    |   DetectionEngine
    |       |
    |       +-- transform with saved scaler/PCA
    |       +-- compute NSA component scores
    |       +-- compute PCA self-boundary weighted score
    |       +-- attach raw self-boundary evidence
    |       +-- apply saved fused threshold
    |       +-- optionally compute post-run labelled verification
    |
    +-- Capture router
            |
            v
        Scapy packets -> flow features -> DetectionEngine -> WebSocket
```

---

## 11. Key Design Decisions

| Decision | Reason |
|---|---|
| CICIDS2017 as the live profile | CICIDS2017 is flow-based and matches live CICFlowMeter-style feature extraction |
| NSL-KDD as batch-only benchmark | NSL-KDD is useful academically but has a different schema, so it cannot drive live capture |
| Split before fitting | Prevents preprocessing leakage |
| BENIGN-only fitting | Keeps the AIS training unsupervised and biologically consistent |
| RobustScaler | Reduces the impact of large CICIDS2017 outliers |
| PCA whitening | Makes distance-based NSA scoring more stable |
| NSA in PCA space | Detector distances are measured in the same transformed feature space |
| PCA Self-Boundary for scoring | Keeps fused scoring in the same PCA geometry as NSA |
| Raw Self-Boundary for evidence | Preserves interpretable feature-boundary explanations |
| Score fusion instead of hard OR | Produces a smoother anomaly score and a controllable FPR |
| Threshold from benign calibration | Keeps threshold selection unsupervised |
| Labels only after detection | Allows honest evaluation without supervised leakage |
| Accuracy is secondary | IDS data is imbalanced, so recall, FNR, FPR, precision, and F1 matter more |
| Live capture has no labelled metrics | Live traffic has no ground-truth labels, so recall/F1 cannot be shown honestly |

---

## 12. Metric Interpretation for Report

Recommended wording:

> The proposed AIS model is trained using only benign traffic. The scaler, PCA transformer, NSA detector repertoire, self-boundary model, score fusion, and anomaly threshold are all fitted or calibrated without attack labels. Attack labels are used only after detection to evaluate the produced anomaly decisions.

> Recall and false negative rate are treated as the main security metrics because missed attacks are more serious than additional alerts. False positive rate is still monitored to control alert fatigue. Accuracy is reported only as a secondary metric because intrusion datasets are often highly imbalanced.

> The Self Intrusion Rate measures how often the AIS mechanism reacts to benign/self traffic. It is interpreted as an autoimmunity check: lower values mean the detector repertoire is less likely to attack self traffic.

> The Silhouette Score is included only as an unsupervised separation indicator. It has limitations because anomaly detection is not pure clustering, and the predicted anomaly group may contain multiple attack behaviours.
