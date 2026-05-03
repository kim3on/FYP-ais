# AIS-Detect Backend
### Web-Based Network Anomaly Detection using Artificial Immune Systems (AIS)
**Project 1627 D — IIUM Kulliyyah of ICT**

---

## 🚀 Recent System Updates (May 2026)

- **Frontend UI/UX Overhaul:** Transitioned to a high-contrast "Cyber-Defense" aesthetic using a refined Rosé Pine theme. Enhanced forensic data visualization and real-time status tracking.
- **Robust AIS Matching:** Refactored the Negative Selection Algorithm (NSA) to use a True V-Detector architecture. Detects known anomalies via variable-radius mature detectors, while using the "Self-gap" fallback mechanism for far-out zero-day spaces.
- **Leakage-Free ML Pipeline:** Refactored the preprocessing and training workflow to eliminate data leakage. The feature scaler is now fitted strictly on training data, ensuring statistically sound benchmarks against Isolation Forest.
- **Code Integrity:** Resolved 49 frontend linting issues and optimized React hook stability.

## Architecture Overview

```
ais-backend/
│
├── app/
│   ├── main.py          # FastAPI Application Factory
│   ├── core/
│   │   ├── detection.py # Live Inference Engine
│   │   ├── pipeline.py  # Leakage-free Training Pipeline
│   │   └── preprocessor.py # CIC-IDS-2017 Feature Processor
│   ├── models/
│   │   ├── nsa.py       # True V-Detector Negative Selection Model
│   │   └── isolation_forest.py # Benchmark Baseline
│   └── artefacts/       # Trained Models & Preprocessor States
│
├── frontend/            # React (Vite) Dashboard
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
- `analysis_ui_ux.md`: Design philosophy and frontend audit.
- `analysis_ais_logic.md`: Immunological matching and forensic scoring details.
- `analysis_ml_validation.md`: Statistical integrity and leakage prevention report.
- `analysis_security_audit.md`: **[CRITICAL]** Brutally critical system security audit.
## API Reference

### Authentication
```
POST /api/auth/login
Body: { "username": "admin", "password": "password" }
```

Default accounts: `admin / password` · `analyst / analyst123`

### Training
```
POST /api/train
  Form field : file  (CSV or Parquet — CIC-IDS-2017 format)
  Query params: r, max_detectors, max_attempts, contamination, test_size

GET  /api/train/logs     → real-time training log lines + status
GET  /api/train/result   → full evaluation results + model metadata
```

### Detection
```
POST /api/detect
  Form field: file  (CSV or Parquet network log)
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

WS   /ws/live             → WebSocket push (snapshot + per-flow updates)
```

### Alerts
```
GET   /api/alerts              → list alerts (?severity=critical, ?limit=100)
GET   /api/alerts/{id}         → single alert detail
PATCH /api/alerts/{id}/fp      → mark as false positive
```

### Dashboard & Settings
```
GET  /api/dashboard/stats      → stat card numbers for the frontend
GET  /api/model/summary        → NSA + IsoForest metadata
GET  /api/system/status        → active status, packet count, antibody count
PATCH /api/settings            → switch active model (nsa | isolation_forest)
GET  /health                   → { status: "ok", version: "4.0.0" }
```

---

## Configuration Parameters

| Parameter        | Default | Description |
|------------------|---------|-------------|
| `r`              | 0.5     | Detector activation radius. Smaller = more precise, fewer FPs. |
| `max_detectors`  | 500     | Max mature antibodies. More = better coverage, slower training. |
| `max_attempts`   | 10,000  | Max random candidates tried during training. |
| `contamination`  | 0.05    | IsoForest: expected fraction of attacks in training data. |
| `test_size`      | 0.2     | Fraction held out for test-set evaluation. |

---

## Dataset Format (CIC-IDS-2017)

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

> **IP / Port metadata:** CICFlowMeter flow-stat files do **not** include source/
> destination IPs or ports. The dashboard displays `N/A` for these fields — this is
> correct behaviour, not a bug. Use raw PCAP exports if you need endpoint metadata.

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

**WARNING:** A comprehensive security audit (May 2026) has identified several **CRITICAL** vulnerabilities in the authentication and WebSocket layers. While the detection engine is robust, the application itself is currently considered a "Security Theatre" implementation and **must not be deployed in production** without implementing the recommendations in `analysis_security_audit.md`.

**Identified Issues:**
- Predictable demo tokens.
- Unauthenticated WebSockets.
- Cleartext password comparison.
- Static radius evasion vectors.

---

## Database Persistence
The system uses a persistent local **SQLite database** (`app/artefacts/ais_detect.db`) managed via **SQLAlchemy ORM**.
- **`alerts`**: Stores every anomaly flagged by the engine.
- **`blocked_ips`**: Persistent registry for inbound Windows Firewall block rules.
- **`raw_flows`**: Archives live packet flows captured by the sniffer.
