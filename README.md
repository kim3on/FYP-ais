# AIS-Detect Backend
### Web-Based Network Anomaly Detection using Artificial Immune Systems (AIS)
**Project 1627 D — IIUM Kulliyyah of ICT**

---

## 🚀 Recent System Updates (May 2026)

### May 17 Update
- **Dataset Profiles:** Added dataset-specific training/detection profiles. CIC-IDS-2017 remains the live-compatible profile; NSL-KDD is supported as a batch-only benchmark with its own preprocessor and model artifacts.
- **Dataset-Specific Artefacts:** Trained models now live under dataset-specific artifact folders, preventing CICIDS2017 and NSL-KDD feature schemas from being mixed.
- **PCA-Space Self-Boundary Fusion:** Added a PCA-space Self-Boundary detector for final fused AIS scoring while keeping raw-feature Self-Boundary evidence for analyst explanations.
- **Frontend Build Optimization:** Route-level lazy loading reduces the initial React bundle, and Vite now cleans old hashed assets during production builds.

### May 15 ML Integrity Update
- **Strict BENIGN-Only Calibration:** NSA, Self-Boundary, PCA-Self-Boundary, Isolation Forest, score scales, and thresholds are fitted/calibrated only from BENIGN training/calibration rows.
- **Conformal Threshold Calibration:** NSA-only, fused AIS, Self-Boundary, and Isolation Forest thresholds use a shared finite-sample conformal helper with calibration reliability metadata.
- **Detector Source Decomposition:** Training and detection reports include source-level evidence such as `v_detector`, `self_gap`, `score_fusion`, and `pca_self_boundary`.
- **Higher NSA Capacity:** Default detector generation increased to `max_detectors=3000` and `max_attempts=100000`.

### May 10 Update
- **Dashboard UI Refresh:** Reworked the dashboard into focused metric cards for total packets, anomalies detected, active antibodies, and zero-day candidates, with live severity indicators.
- **Accessibility & Help Centre:** Added a dedicated Accessibility page with getting-started guidance, FAQ, glossary, troubleshooting notes, and WCAG-oriented usability information.
- **Settings Experience:** Refined the settings interface for active model selection, alert threshold configuration, raw-flow cleanup, and system/model visibility.

### May 6 Security & ML Update
- **JWT Authentication:** Replaced demo tokens with signed JWT authentication. Passwords are stored as bcrypt hashes, and non-health API routes now require authenticated access.
- **Secured WebSocket Access:** Live WebSocket connections now require a valid token instead of exposing alert snapshots publicly.
- **Alert Summary Export:** Added a backend-generated alert summary CSV with severity and attack-family rollups, top sources/targets, repeated endpoint pairs, priority incidents, and action-code guidance.
- **PCA-Safe NSA Geometry:** Updated the preprocessing/model path to use RobustScaler + PCA whitening, dynamic NSA thresholds, and detector generation in the actual PCA feature space instead of assuming `[0, 1]` bounds.
- **False Positive Rate Visibility:** Exposed FPR in training/detection result views to make model evaluation more useful for FYP analysis.

### Earlier May Update
- **True V-Detector NSA:** Refactored the Negative Selection Algorithm to use variable-radius mature detectors with self-gap fallback for novel anomaly space.
- **Leakage-Free ML Pipeline:** The feature transformer is fitted strictly on training data before held-out evaluation, reducing test-set leakage.
- **Frontend UI/UX Overhaul:** Transitioned to a high-contrast cyber-defense interface with improved forensic visualization and live status tracking.

## Architecture Overview

```
ais-backend/
│
├── app/
│   ├── main.py          # FastAPI Application Factory
│   ├── core/
│   │   ├── detection.py # Live Inference Engine
│   │   ├── pipeline.py  # Leakage-free Training Pipeline
│   │   ├── preprocessor.py # CIC-IDS-2017 Feature Processor
│   │   ├── nsl_kdd_preprocessor.py # NSL-KDD Batch Benchmark Processor
│   │   └── datasets.py  # Dataset profile + artefact path helpers
│   ├── models/
│   │   ├── nsa.py       # True V-Detector Negative Selection Model
│   │   ├── self_boundary.py # Quantile-fence Self-Boundary Model
│   │   └── isolation_forest.py # Benchmark Baseline
│   └── artefacts/       # Dataset-specific models, DB, and runtime state
│
├── frontend/            # React (Vite) Dashboard
│   ├── src/pages/       # Dashboard, Training, Detection, Alerts, Settings, Accessibility
│   ├── src/hooks/       # Optimized Custom Hooks (useApp, useAuth)
│   └── src/styles/      # Modern Cyber-Defense Global Styles
│
└── validate and test/   # Test Suites & Auditors
    ├── test_backend.py  # Comprehensive Test Suite (28 tests)
    └── validate_ml.py   # ML Statistical Integrity Auditor
```

---

## How the AIS Works

### Biological Analogy
The human immune system distinguishes **Self** (your own cells) from **Non-Self**
(pathogens). T-cells that would attack Self are eliminated in the thymus — this is
*negative selection*. The surviving T-cells only react to Non-Self (infections).

### Mapping to Network Security
| Biology             | AIS-Detect                 |
|---------------------|----------------------------|
| Self (own cells)    | Normal network traffic     |
| Non-Self (pathogen) | Attack / anomaly           |
| T-cell candidate    | Random detector vector     |
| Thymus selection    | Negative selection step    |
| Mature antibody     | Stored detector            |
| Immune response     | Anomaly alert              |

### True V-Detector Negative Selection Algorithm
The current implementation uses a **V-Detector Inference Engine**:
1. **Adaptive Immune Response (Primary):** Network flows are checked against the mature V-Detector repertoire. Any flow falling within a detector's variable radius (`r = dist_to_nearest_self - r_s`) is immediately flagged as an anomaly.
2. **Innate Immune Fallback (Zero-Day):** Due to the curse of dimensionality, detectors cannot cover the entire 77-dimensional space. Any flow falling far outside the learned "Self" manifold (exceeding self-gap threshold `r`) is flagged as a zero-day anomaly.
3. **Boundary Mutation & Aging:** Antibody generation uses K-Means centroids and Gaussian mutation near the Self-boundary to minimize evasion "holes", while an active-aging mechanism (`refresh()`) simulates T-Cell death and replacement.

---

## 🚀 Getting Started

1. **Environment:**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Run Tests:**
   ```powershell
   cd "validate and test"
   python test_backend.py  # Backend & Model Tests
   python validate_ml.py   # ML Integrity Audit
   ```

3. **Frontend Build:**
   ```powershell
   cd frontend
   npm install
   npm run build
   ```

4. **Launch Server:**
   ```powershell
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

---

## 📋 Technical Documentation
Detailed technical analyses are available in the project root:
- `analysis/analysis_ui_ux.md`: Design philosophy and frontend audit.
- `analysis/analysis_ais_logic.md`: Immunological matching and forensic scoring details.
- `analysis/analysis_ml_validation.md`: Statistical integrity and leakage prevention report.
- `analysis/analysis_security_audit.md`: Security audit baseline and original risk register.
- `analysis/fix 6 may/auth fix.md`: JWT, bcrypt, route protection, and WebSocket auth plan/summary.
- `analysis/fix 6 may/csv_analysis.md`: Analytical CSV export design.
- `analysis/fix 6 may/threshold calibration and correct PCA-space detector geometry.md`: RobustScaler + PCA + dynamic NSA threshold rationale.
- `analysis/fix 10 may/implementation_plan ui dashboard.md`: Dashboard metric card redesign plan.
- `analysis/fix 10 may/implementation_plan accesibility.md`: Accessibility and help-centre page plan.

## API Reference

### Authentication
```
POST /api/auth/login
Body: { "username": "admin", "password": "password" }
Returns: { success, username, role, token }
```

Default seeded accounts: `admin / password` · `analyst / analyst123`

All non-health API calls should include:

```
Authorization: Bearer <jwt-token>
```

### Training
```
POST /api/train
  Form field : file
  Query params: dataset_type, r, r_s, max_detectors, max_attempts,
                contamination, test_size, target_fpr, benign_row_limit

Supported dataset profiles:
  cicids2017  → CSV / Parquet, live-compatible
  nsl_kdd     → CSV only, batch benchmark

GET  /api/train/logs     → real-time training log lines + status
GET  /api/train/result   → full evaluation results + model metadata
```

### Detection
```
POST /api/detect
  Form field: file
  Query params: dataset_type, limit, offset
  Returns: { total_checked, anomalies_found, alerts, severity_counts, ... }

GET  /api/detect/logs    → streaming detection log + status
GET  /api/detect/result  → last completed detection result

POST /api/detect/sample
  Body: { feature dict for one network flow }
```

### Live Packet Capture
```
POST /api/capture/start   → start scapy sniffer (requires root/admin)
POST /api/capture/stop    → stop capture
GET  /api/capture/status  → live counters
GET  /api/capture/interfaces → available network interfaces
GET  /api/capture/chartdata  → 60-point ring buffer for polling fallback

WS   /ws/live?token=<jwt> → WebSocket push (snapshot + per-flow updates)
```

### Alerts
```
GET   /api/alerts              → list alerts (?severity=critical, ?limit=100)
GET   /api/alerts/{id}         → single alert detail
PATCH /api/alerts/{id}/fp      → mark as false positive
DELETE /api/alerts             → clear stored alerts

GET   /api/alerts/export.csv   → alert summary CSV export
  Query params: from, to, severity, attack_type, include_false_positive, zero_day_only
```

The CSV export is generated from the SQLite alert database, not only the visible
frontend table. It is a sectioned triage report with a report overview, severity
and attack-family summaries, top sources/targets, repeated endpoint pairs,
priority incidents, and an action legend for FYP reporting and analyst review.

### Dashboard & Settings
```
GET  /api/dashboard/stats      → stat card numbers for the frontend
GET  /api/model/summary        → NSA + IsoForest metadata
GET  /api/system/status        → active status, dataset profile, packet count, antibody count
PATCH /api/settings            → switch active model (nsa | isolation_forest)
GET  /health                   → { status: "ok", version: "4.0.0" }
```

---

## Configuration Parameters

| Parameter        | Default | Description |
|------------------|---------|-------------|
| `dataset_type`   | `cicids2017` | Dataset profile. Use `cicids2017` for live-compatible flow features or `nsl_kdd` for batch-only benchmark CSVs. |
| `r`              | `0.3` via API | NSA self-gap threshold. Samples far from all self references can be flagged through the self-gap path. |
| `r_s`            | `0.03` via API | Self-tolerance margin for negative selection. Smaller values let detectors sit closer to the self boundary. |
| `max_detectors`  | `3,000` | Max mature V-detectors. More = better coverage, slower training. |
| `max_attempts`   | `100,000` | Max random candidates tried during training. |
| `target_fpr`     | `0.05` | BENIGN calibration target for NSA/fusion/Self-Boundary/Isolation Forest thresholds. |
| `benign_row_limit` | `20,000` | Optional cap on BENIGN rows used for laptop-friendly training. |
| `contamination`  | `0.05` | Isolation Forest fallback contamination; calibrated threshold is preferred. |
| `test_size`      | 0.2     | Fraction held out for test-set evaluation. |
| `n_pca_components` | `0.95` lower-level default | PCA variance target/component setting used by preprocessors. |

Current preprocessing flow:

```
Raw CIC-IDS-2017 features
→ clean Inf / NaN / duplicate columns
→ RobustScaler
→ PCA(whiten=True)
→ NSA V-detectors + PCA Self-Boundary fusion / Isolation Forest baseline
```

---

## Dataset Profiles

### CIC-IDS-2017

The system is trained on **CIC-IDS-2017** (Canadian Institute for Cybersecurity),
exported from CICFlowMeter as CSV. Key properties:

- **~80 numerical flow-stat features** (packet lengths, IAT, flags, ratios, …)
- **Label column:** `" Label"` (note leading space from CICFlowMeter)
- **Normal label:** `"BENIGN"` — all other labels are treated as attacks
- **Common attack labels:** DoS Hulk, DDoS, PortScan, Bot, Infiltration, …
- **Known quirks handled automatically:**
  - `Inf` strings in `Flow Bytes/s` / `Flow Packets/s` → replaced with `0`
  - Duplicate `Fwd Header Length.1` column → dropped
  - Leading/trailing whitespace in column names → stripped

**Download CIC-IDS-2017:** https://www.unb.ca/cic/datasets/ids-2017.html
**Download CIC-IDS-2017:** https://www.kaggle.com/datasets/dhoogla/cicids2017
**Download CIC-IDS-2017:** https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset

> **IP / Port metadata:** Some prepared CICFlowMeter flow-stat files do not include source/destination IPs or ports. The dashboard displays `N/A` for missing fields. Use raw PCAP-derived exports if endpoint metadata is required.

### NSL-KDD Benchmark

NSL-KDD is supported as a **batch-only benchmark profile**:

- Accepted format: CSV with NSL-KDD headers.
- Uses `app/core/nsl_kdd_preprocessor.py`.
- Stores its own models under `app/artefacts/nsl_kdd/`.
- Cannot be used for live capture because NSL-KDD does not share the CICFlowMeter feature schema.

### Artifact Layout

```text
app/artefacts/
  ais_detect.db
  runtime_settings.json
  cicids2017/
    nsa_model.pkl
    iso_model.pkl
    preprocessor.pkl
    self_boundary.pkl
    pca_self_boundary.pkl
    last_train_result.json
  nsl_kdd/
    nsa_model.pkl
    iso_model.pkl
    preprocessor.pkl
    self_boundary.pkl
    pca_self_boundary.pkl
    last_train_result.json
```

---

## Alert Severity Mapping

| Confidence Score | Severity |
|-----------------|----------|
| ≥ 90%           | Critical |
| ≥ 75%           | High     |
| ≥ 50%           | Medium   |
| < 50%           | Low      |

---

## 🔒 Security Status

The May 6 update addresses the original critical demo-auth findings:

- Demo tokens were replaced with signed JWTs.
- Default seeded passwords are hashed with bcrypt.
- Training, detection, alerts, capture, dashboard stats/settings, and firewall routes are protected by authentication dependencies.
- Live WebSocket access requires a token.

Remaining deployment hardening before public production use:

- Set `AIS_SECRET_KEY`; otherwise the app uses a local-development fallback secret and logs a warning.
- Set `AIS_ADMIN_PASSWORD` and `AIS_ANALYST_PASSWORD` before public deployment.
- Add role-specific authorization for destructive admin actions.
- Restrict CORS origins for deployed environments.
- Replace SQLite with a managed database for multi-user/cloud deployment.
- Move long-running training/detection jobs to a durable job queue if used beyond demo scale.

---

## Database Persistence
The system uses a persistent local **SQLite database** (`app/artefacts/ais_detect.db`) managed via **SQLAlchemy ORM**.
- **`alerts`**: Stores every anomaly flagged by the engine.
- **`blocked_ips`**: Persistent registry for inbound Windows Firewall block rules.
- **`raw_flows`**: Archives live packet flows captured by the sniffer.
