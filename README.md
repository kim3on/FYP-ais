# AIS-Detect Backend
### Web-Based Network Anomaly Detection using Artificial Immune Systems (AIS)
**Project 1627 D — IIUM Kulliyyah of ICT**

---

## Architecture Overview

```
ais-backend/
│
├── app/
│   ├── main.py                    ← Thin FastAPI app factory (registers routers)
│   ├── state.py                   ← Shared in-memory state + _build_engine()
│   ├── schemas.py                 ← Pydantic request/response models
│   │
│   ├── routers/                   ← One file per feature area (all < 600 lines)
│   │   ├── auth.py                ← POST /api/auth/login
│   │   ├── training.py            ← POST /api/train, GET /api/train/logs|result
│   │   ├── detection.py           ← POST /api/detect, GET /api/detect/logs|result
│   │   ├── alerts.py              ← GET/PATCH /api/alerts/*
│   │   ├── capture.py             ← POST/GET /api/capture/*, WS /ws/live
│   │   └── dashboard.py           ← Stats, model info, settings, health, landing page
│   │
│   ├── models/
│   │   ├── nsa.py                 ← Negative Selection Algorithm (core AIS)
│   │   └── isolation_forest.py    ← Isolation Forest baseline model
│   │
│   ├── core/
│   │   ├── preprocessor.py        ← CIC-IDS-2017 data loading, encoding, scaling
│   │   ├── pipeline.py            ← Full training pipeline (Train → Evaluate → Save)
│   │   ├── detection.py           ← Live/batch detection engine + alert generation
│   │   ├── capture.py             ← Live packet capture (scapy + FlowAggregator)
│   │   └── evaluator.py           ← Metrics: accuracy, precision, recall, F1, FPR
│   │
│   └── js/                        ← Frontend (served as static files)
│       ├── ais-detect.css         ← Design system — tokens, components, utilities
│       ├── api.js                 ← Fetch wrapper (GET / POST / PATCH / postForm)
│       ├── state.js               ← Shared app state + DOM helpers
│       ├── theme.js               ← Theme toggle, toast, connection indicator, clock
│       ├── auth.js                ← Login / logout
│       ├── nav.js                 ← Panel routing + resize
│       ├── charts.js              ← Canvas traffic chart + AIS scatter plot
│       ├── dashboard.js           ← Stats fetching + alert table renders
│       ├── training.js            ← Upload, log polling, result display
│       ├── detection.js           ← Batch detect, result render, CSV export
│       ├── capture.js             ← WebSocket, live flows table, capture controls
│       ├── settings.js            ← Model switch + profile render
│       └── init.js                ← App init + startup health check
│
├── artefacts/                     ← Saved models (auto-created after training)
│   ├── nsa_model.pkl
│   ├── iso_model.pkl
│   ├── preprocessor.pkl
│   └── last_train_result.json
│
├── test_backend.py                ← 26-test suite (no FastAPI/network needed)
├── requirements.txt
└── README.md
```

**File-size constraint:** Every source file is kept under **600 lines** to maintain
readability. The router/JS split enforces single-responsibility across the codebase.

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

### Negative Selection Algorithm (NSA) Steps

```
1. TRAINING PHASE
   ┌─────────────────────────────────────────┐
   │  Input: Clean (normal) network traffic   │
   │                                          │
   │  ① Normalise features to [0, 1]ⁿ        │
   │  ② Define Self = all normal samples      │
   │  ③ Generate random candidate detector d  │
   │  ④ If dist(d, Self) < r → REJECT (would  │
   │     misfire on normal traffic)           │
   │  ⑤ Else → KEEP as mature antibody        │
   │  ⑥ Repeat until max_detectors stored     │
   └─────────────────────────────────────────┘

2. DETECTION PHASE
   ┌─────────────────────────────────────────┐
   │  Input: Live/uploaded network traffic   │
   │                                         │
   │  For each flow x:                       │
   │    If dist(x, any_detector) < r         │
   │      → ANOMALY (Non-Self detected)      │
   │    Else                                 │
   │      → NORMAL                           │
   └─────────────────────────────────────────┘
```

**Distance metric:** Normalised Euclidean distance across all ~75 CIC-IDS-2017 features.

**Confidence score:** `1 - (min_dist_to_detector / (r × 3))`, clamped to [0, 1].

---

## Quick Start

### 1. Create a virtual environment and install dependencies
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Run the API server
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

- **Interactive API docs:** http://localhost:8000/docs
- **Landing page:** http://localhost:8000/
- **Health check:** http://localhost:8000/health

### 3. Open the dashboard
Open `app/ais-detect-live.html` directly in a browser. No build step required —
it loads the JS modules from `app/js/` via `<script src="js/...">` tags.

> Make sure the backend is running on `http://localhost:8000` before logging in.

### 4. Run the test suite (no server required)
```bash
python test_backend.py
```

The suite generates synthetic CIC-IDS-2017 data internally — no dataset download needed.

---

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

## Frontend Connection

The dashboard (`app/ais-detect-live.html`) connects to the backend at:

```javascript
// app/js/api.js — change if your server runs on a different host/port
const API = 'http://localhost:8000';
```

All endpoints return JSON with CORS enabled for all origins. The frontend uses:
- **REST polling** (`/api/train/logs`, `/api/detect/logs`) for training/detection progress
- **WebSocket** (`/ws/live`) for real-time live capture updates

---

## Notes on Real-World Performance

- The NSA works best when trained on **clean normal traffic only**.
  If the training set contains hidden attacks, the Self profile is poisoned.
- The Pre-Training Validation panel (Training page) shows dataset stats before
  training starts — use this to confirm the BENIGN/attack split is as expected.
- Use the **Isolation Forest** baseline when you cannot guarantee a clean training set
  (it tolerates mixed contamination via the `contamination` parameter).
- **Live packet capture** requires root/admin privileges and `scapy` installed.
  On Windows, install [Npcap](https://npcap.com/) first.
- For production: replace the in-memory alert store with SQLite/PostgreSQL,
  add proper JWT auth, and scope CORS origins.
