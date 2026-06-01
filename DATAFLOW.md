# AIS-Detect Data Flow

> - Project: Web-Based Network Anomaly Detection using Artificial Immune Systems
> - Backend: FastAPI, Python, SQLite, Scapy/CICFlowMeter-style flow extraction
> - Frontend: React + Vite
> - Main dataset profile: CICIDS2017 flow records
> - Batch benchmark profile: NSL-KDD
> - Main detector: Negative Selection Algorithm with V-detectors
> - Baseline detector: Isolation Forest

---

## 1. Architecture Summary

AIS-Detect has three main workflows:

| Workflow | Purpose |
|---|---|
| Training | Learn the benign/self traffic profile |
| Batch Detection | Analyse uploaded CICIDS2017/NSL-KDD-style files |
| Live Capture | Convert live packets into CICIDS2017-style flows and score them |

The core design is unsupervised:

- The scaler, representation layer, NSA, Self-Boundary models, Isolation Forest, and thresholds are fitted/calibrated using BENIGN rows only.
- Attack labels are not used to fit the detector or choose thresholds.
- Labels, when available, are used only after prediction for verification metrics.
- The main model output is binary: `Normal` or `Anomaly`.
- Attack family, zero-day candidate, direction, and analyst notes are post-detection interpretation layers.

Dataset profiles are separated so incompatible feature schemas are not mixed:

| Profile | Use | Live capture | Artifact folder |
|---|---|---|---|
| `cicids2017` | Main CICFlowMeter-style IDS workflow | Yes | `app/artefacts/cicids2017/` |
| `nsl_kdd` | Offline benchmark workflow | No | `app/artefacts/nsl_kdd/` |

---

## 2. Startup Flow

```text
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

1. FastAPI starts and registers routers.
2. SQLite tables are created if missing.
3. Existing SQLite installs are repaired with any missing nullable alert columns.
4. Default users are seeded if the user table is empty.
5. Existing firewall block records are loaded into memory.
6. If `app/static_react/` exists, FastAPI serves the built React dashboard.

Main routers:

| Router | Responsibility |
|---|---|
| `auth` | Login, JWT authentication |
| `training` | Dataset upload, model training, training logs, training-run CSV |
| `detection` | Batch detection on uploaded files |
| `capture` | Live packet capture, PCAP/manual flow submission, WebSocket updates |
| `alerts` | Alert list, false-positive marking, summary/raw CSV export |
| `dashboard` | Status, dashboard summary, runtime settings |
| `firewall` | Manual Windows Firewall block/unblock |
| `users` | Admin user management |

---

## 3. Authentication Flow

```text
Browser
  -> POST /api/auth/login
  <- JWT token + role
```

- Passwords are checked against bcrypt hashes in SQLite.
- The frontend stores the JWT in React context/local runtime state.
- HTTP calls send `Authorization: Bearer <token>`.
- WebSocket clients connect using `/ws/live?token=<jwt>`.
- Invalid WebSocket tokens are rejected before the socket is accepted.
- Training, detection, capture control, firewall actions, user management, and alert exports require authentication.

---

## 4. Training Flow

Training teaches AIS-Detect what normal/self traffic looks like.

```text
Browser
  -> POST /api/train
  <- "Training started"
```

The backend:

1. Reads uploaded CSV/Parquet bytes.
2. Selects the dataset profile.
3. Starts `TrainingPipeline.run()` in the background.
4. Streams progress through `GET /api/train/logs`.
5. Saves models and a training-run summary when finished.

### 4.1 Benign-Only Split

```text
Uploaded dataset
    |
    v
Load CSV / Parquet
    |
    v
Find label column
    |
    v
Map labels:
    BENIGN/normal -> self traffic
    attack labels -> report-only verification pool
    |
    v
Keep BENIGN rows for fitting/calibration
    |
    v
Split BENIGN rows:
    train       -> fit scaler, representation, NSA, Self-Boundary, Isolation Forest
    calibration -> calibrate benign thresholds and score scales
    test        -> benign holdout FPR / self-intrusion check
```

Attack rows are not used for model fitting or threshold selection.

### 4.2 Representation / Preprocessing

Files:

- `app/core/preprocessor.py` for CICIDS2017.
- `app/core/nsl_kdd_preprocessor.py` for NSL-KDD.

Default production path:

```text
BENIGN train rows
    |
    v
Clean columns, replace Inf/NaN, drop duplicates/metadata
    |
    v
Fit RobustScaler on BENIGN train only
    |
    v
Fit PCA(whiten=True) on BENIGN train only
    |
    v
Transform train / calibration / test / detection rows using saved scaler + PCA
```

Experimental developer path:

```text
?dev=1 in frontend
    |
    v
CICIDS2017 Training tab exposes PCA / Denoising AE selector
    |
    v
DAE trains only on BENIGN training rows after RobustScaler
```

DAE is hidden from normal users, CICIDS2017-only, and used only for experiments. PCA remains the default and public path.

Important leakage rule:

```text
No calibration, test, or detection rows are used to fit RobustScaler, PCA, or DAE.
```

### 4.3 NSA V-Detector Training

File: `app/models/nsa.py`

```text
BENIGN training rows in saved representation space
    |
    v
Build self-reference set
    |
    v
Generate candidate detectors
    |
    v
Reject candidates that react to self
    |
    v
Store mature detector center + variable radius
```

Detector generation and inference happen in the saved representation space, not in raw `[0, 1]` feature space. This avoids the old PCA geometry mismatch.

### 4.4 Threshold Calibration

Final NSA decision is:

```text
anomaly = mature V-detector match OR calibrated self-gap threshold exceeded
```

Calibration uses BENIGN calibration rows only:

```text
BENIGN calibration rows
    |
    v
Measure detector-only benign matches
    |
    v
Use remaining target FPR budget for self-gap threshold
    |
    v
Save threshold, score scale, observed benign FPR, and reliability metadata
```

Default target FPR is `0.10` and is configurable from the Training tab between `0.01` and `0.20`. Batch and live detection use the saved calibrated threshold after retraining.

### 4.5 Self-Boundary Evidence

File: `app/models/self_boundary.py`

AIS-Detect stores two Self-Boundary models:

| Model | Space | Purpose |
|---|---|---|
| Raw Self-Boundary | Cleaned raw feature space | Human-readable evidence |
| Representation Self-Boundary | PCA/DAE space | Supporting evidence |

Self-Boundary no longer controls the final AIS decision. It is retained to explain why an alert looks unusual.

### 4.6 Isolation Forest Baseline

Isolation Forest is trained on BENIGN rows only and calibrated with BENIGN calibration rows. It is a selectable baseline engine, not the main AIS mechanism.

### 4.7 Training Outputs

Training saves:

| Artifact | Purpose |
|---|---|
| `app/artefacts/<dataset>/nsa_model.pkl` | NSA detectors, self-reference set, threshold calibration |
| `app/artefacts/<dataset>/iso_model.pkl` | Isolation Forest baseline |
| `app/artefacts/<dataset>/preprocessor.pkl` | RobustScaler, PCA/DAE, feature schema |
| `app/artefacts/<dataset>/self_boundary.pkl` | Raw feature-boundary evidence model |
| `app/artefacts/<dataset>/pca_self_boundary.pkl` | Representation-space evidence model |
| `app/artefacts/<dataset>/last_train_result.json` | Last training summary |
| `app/artefacts/training_runs.jsonl` | Compact historical training-run records |

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
Load saved preprocessor + selected model
    |
    v
Transform rows with saved RobustScaler + PCA/DAE
    |
    v
NSA:
    V-detector match OR self-gap threshold -> anomaly

Isolation Forest:
    raw anomaly score > benign-calibrated threshold -> anomaly
    |
    v
Build alert records for anomalous rows
```

Detection labels are not read until after predictions are complete.

### 5.1 Confidence Score

The UI confidence is the normalized anomaly strength returned by the selected unsupervised model.

For NSA:

```text
confidence = max(
    normalized self-gap distance above threshold,
    mature V-detector match strength
)
```

For Isolation Forest:

```text
confidence = normalized raw anomaly score above its benign-calibrated threshold
```

The alert stores:

```text
confidence      -> numeric score in [0, 1]
confidence_pct  -> rounded percentage for display
```

Defense wording:

> Confidence is not ground-truth probability. It is the normalized anomaly strength produced by the unsupervised detector after benign calibration.

### 5.2 Severity Mapping

| Confidence Score | Severity |
|---|---|
| `>= 0.90` | Critical |
| `>= 0.75` | High |
| `>= 0.50` | Medium |
| `< 0.50` | Low |

### 5.3 Attack Family and Zero-Day Candidate

Layer 2 runs only after Layer 1 has flagged an anomaly.

```text
Anomalous row
    |
    v
Try flow-feature heuristics:
    Brute Force, DDoS, DoS, Port Scan, Web Attack,
    Botnet, Data Exfiltration, Heartbleed, etc.
    |
    v
If no known pattern matches:
    score >= zero_day_threshold -> Zero-Day Candidate
    score <  zero_day_threshold -> Unknown Anomaly
```

Default zero-day threshold is `0.65` and can be changed in Settings.

Defense wording:

> A zero-day candidate is not a confirmed zero-day. It is a high-novelty anomaly that did not match the known flow-pattern heuristics.

### 5.4 Direction Layer

File: `app/core/endpoint_roles.py`

Direction is a post-detection metadata layer:

| Condition | Direction |
|---|---|
| local source -> external destination | `outbound` |
| external source -> local destination | `inbound` |
| local-local, external-external, or missing IPs | `unknown` |

Default local CIDRs:

```text
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
```

This layer does not decide anomaly status and does not claim attacker identity.

### 5.5 Labelled Verification

If the uploaded detection file has labels, the backend computes report-only metrics after prediction:

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
| Accuracy | Secondary metric under class imbalance |

These metrics are not fed back into the model.

### 5.6 Threshold Trade-Off Analysis

For labelled files, the system can evaluate report-only threshold trade-offs:

```text
threshold -> recall, FNR, FPR, precision, F1
```

This does not automatically change the saved unsupervised model threshold.

---

## 6. Live Capture Flow

Live capture uses the CICIDS2017 profile only.

```text
Network interface
    |
    v
Scapy / CICFlowMeter-style flow adapter
    |
    v
Completed flow features + metadata
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

Live mode has no ground-truth labels. It can show flow counts, anomaly counts, severity, direction, and alert records, but it cannot honestly show recall, precision, F1, or FNR.

---

## 7. Alert Persistence and Export

Alert flow:

```text
DetectionEngine creates AlertRecord
    |
    +-> batch result memory for Detection page
    |
    +-> live/manual capture writes AlertDB rows
    |
    +-> frontend fetches stored alerts through /api/alerts
```

SQLite alert records include:

- raw source/destination metadata when available
- confidence and severity
- zero-day flag
- false-positive status
- direction fields
- raw flow feature snapshot where available

Exports:

| Endpoint | Purpose |
|---|---|
| `GET /api/alerts/export.csv` | Sectioned analytical summary CSV |
| `GET /api/alerts/export_raw.csv` | Flat alert-row CSV |
| `GET /api/train/runs/export.csv` | Historical training-run comparison CSV |

The alert summary CSV is generated from SQLite, not only currently visible frontend rows. It includes report overview, severity summary, attack-family summary, direction summary, top sources/targets, top remote endpoints, repeated endpoint pairs, priority incidents, and action legend.

---

## 8. Frontend Data Flow

Main pages:

| Page | Data |
|---|---|
| Dashboard | System status, live counters, live traffic graph, recent non-hidden alerts |
| Train & Detect | Training upload, detection upload, metrics, logs |
| Alerts | Stored alert table, filtering, false-positive marking, CSV export |
| Settings | Model/runtime settings, data management, zero-day threshold |
| Users | Admin user management |

Training page:

```text
POST /api/train
GET /api/train/logs
GET /api/train/result
```

Detection page:

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

Developer representation mode:

```text
?dev=1 -> show CICIDS2017 PCA / DAE selector
?dev=0 -> hide developer controls
```

---

## 9. Runtime State and Database

Runtime state is held in `app/state.py` for the current process:

| State field | Meaning |
|---|---|
| `status` | `idle`, `learning`, `active`, or `error` |
| `training_logs` | Training log lines streamed to frontend |
| `detect_logs` | Detection log lines streamed to frontend |
| `active_model` | `nsa` or `isolation_forest` |
| `active_dataset_type` | `cicids2017` or `nsl_kdd` |
| `zero_day_threshold` | Runtime zero-day candidate threshold |
| `capture_active` | Whether live capture is running |
| `last_detect_result` | Last batch detection result |

Persistent SQLite tables:

| Table | Purpose |
|---|---|
| `users` | Login users and bcrypt password hashes |
| `user_profiles` | User profile metadata |
| `alerts` | Persisted anomaly alerts |
| `blocked_ips` | Firewall block records |
| `raw_flows` | Lightweight live/manual flow log |

Runtime settings persist in `app/artefacts/runtime_settings.json`.

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
    |       +-- CICIDSPreprocessor / NSLKDDPreprocessor
    |       |       fit RobustScaler + PCA or dev-only DAE on BENIGN train only
    |       |
    |       +-- NegativeSelectionDetector
    |       |       train mature V-detectors in saved representation space
    |       |
    |       +-- SelfBoundaryDetector
    |       |       train evidence-only raw/representation boundary models
    |       |
    |       +-- IsolationForestDetector
    |       |       train BENIGN-only baseline
    |       |
    |       +-- Calibration
    |               set BENIGN-only thresholds and score scales
    |
    +-- Detection router
    |       |
    |       v
    |   DetectionEngine
    |       |
    |       +-- transform with saved representation
    |       +-- selected model predicts normal/anomaly
    |       +-- attach confidence, severity, attack family, zero-day flag
    |       +-- attach simple inbound/outbound/unknown direction
    |       +-- optionally compute post-run labelled verification
    |
    +-- Capture router
            |
            v
        live/manual flows -> DetectionEngine -> SQLite/WebSocket/dashboard
```

---

## 11. Key Design Decisions

| Decision | Reason |
|---|---|
| CICIDS2017 as live profile | It matches CICFlowMeter-style flow features used by live capture |
| NSL-KDD as batch-only benchmark | Its feature schema does not match CICFlowMeter live capture |
| Split before fitting | Prevents preprocessing leakage |
| BENIGN-only fitting | Keeps the AIS framework unsupervised |
| RobustScaler | Reduces the impact of large CICIDS2017 outliers |
| PCA whitening by default | Stabilizes distance-based NSA scoring |
| DAE hidden behind dev mode | Allows experimentation without changing the public/default model |
| NSA in representation space | Detector distances match the transformed feature geometry |
| Final AIS decision = V-detector OR self-gap | Keeps the decision rule explainable and immunology-aligned |
| Self-Boundary as evidence | Provides supporting explanation without hidden score fusion |
| Target FPR from benign calibration | Controls expected benign alert rate without attack labels |
| Labels only after detection | Allows honest evaluation without supervised leakage |
| Confidence as anomaly strength | Avoids claiming probability of attack |
| Zero-day as candidate only | Prevents overclaiming unknown anomalies as confirmed attacks |
| Direction-only endpoint layer | Keeps endpoint interpretation simple and defendable |
| Live capture has no labelled metrics | Live traffic has no ground truth |

---

## 12. Report Wording

Recommended wording:

> AIS-Detect trains on benign traffic only. The scaler, representation layer, NSA detector repertoire, Self-Boundary evidence models, Isolation Forest baseline, and thresholds are fitted or calibrated without attack labels. Attack labels are used only after prediction to evaluate the produced anomaly decisions.

> The main detector output is binary normal/anomaly. Attack family and zero-day candidate labels are post-detection explanations and do not control the anomaly decision.

> Confidence is interpreted as normalized anomaly strength, not a probability that the flow is malicious.

> A zero-day candidate is a high-novelty anomaly that does not match the known flow-pattern attribution rules. It is a candidate for analyst review, not proof of a real zero-day attack.

> Direction is derived only from source/destination IP metadata relative to configured local CIDR ranges. It is shown as inbound, outbound, or unknown and does not identify the attacker with certainty.
