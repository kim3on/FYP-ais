# AIS-Detect — End-to-End Data Flow

> **Project:** Web-Based Network Anomaly Detection using Artificial Immune Systems (AIS)  
> **Stack:** FastAPI (Python) · React + Vite (Frontend) · SQLite (SQLAlchemy) · Scapy  
> **Dataset:** CIC-IDS-2017 (8 CSV files, ~2.8 M rows)

---

## System Overview

The system has **two independent operating modes** that share the same trained model artefacts:

| Mode | Entry Point | Use Case |
|------|-------------|----------|
| **Training** | User uploads CSV → `/api/train` | Teach the models what "normal" looks like |
| **Batch Detection** | User uploads CSV → `/api/detect` | Analyse a historical log file offline |
| **Live Detection** | Start capture → `/api/capture/start` | Real-time packet-level anomaly detection |

---

## Phase 1 — Application Startup

```
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

1. **FastAPI app factory** (`app/main.py`) is created.
2. **CORS middleware** is added (allows all origins in dev).
3. **Seven routers** are registered:
   - `auth` · `training` · `detection` · `alerts` · `capture` · `dashboard` · `firewall`
4. **`on_startup` event** runs:
   - `Base.metadata.create_all()` — creates SQLite tables (`users`, `alerts`, `blocked_ips`, `raw_flows`) if they don't exist.
   - Seeds two default users (`admin`, `analyst`) if the `users` table is empty.
   - Loads any persisted **blocked IPs** from the DB into the in-memory `_blocked_ips` dict.
5. If `app/static_react/` exists (production build), FastAPI serves the React SPA as static files.

---

## Phase 2 — User Authentication

```
Browser → POST /api/auth/login  { username, password }
       ← { token, role }
```

- `app/routers/auth.py` verifies the user against the `users` SQLite table.
- Passwords are stored as bcrypt hashes, not plaintext.
- On success, a signed JWT is returned and stored in the frontend React context (`AuthContext`).
- All subsequent HTTP API calls include `Authorization: Bearer <token>`.
- Live WebSocket clients pass the same JWT as `/ws/live?token=<token>`; invalid or missing tokens are rejected before the socket is accepted.

---

## Phase 3 — Model Training Pipeline

This is the **core learning phase**, analogous to the biological thymus educating T-cells.

### 3.1 Dataset Upload

```
User selects CSV (e.g. Wednesday-workingHours.pcap_ISCX.csv)
Browser → POST /api/train  (multipart/form-data, ~225 MB)
        ← { message: "Training started", status: "learning" }
```

- `app/routers/training.py` reads the file bytes into memory.
- Sets `_state["status"] = "learning"`.
- Dispatches `run_training()` as a **FastAPI BackgroundTask** — returns immediately to the client.
- Frontend polls `GET /api/train/logs` every second to stream progress.

### 3.2 TrainingPipeline.run() — `app/core/pipeline.py`

```
dataset_bytes
    │
    ▼
CICIDSPreprocessor._load()          ← Step 1: Parse CSV / Parquet
    │
    ▼
_find_label_col() + _encode_labels() ← Step 2: Binary labels (0=BENIGN, 1=Attack)
    │                                            + attack_category column
    ▼
train_test_split(stratify=y)         ← Step 3: 80/20 split on RAW data
    │                                            (prevents data leakage)
    ├── df_train_raw  (80%)
    └── df_test_raw   (20%)
    │
    ▼
CICIDSPreprocessor.fit(df_train_raw) ← Step 4: Fit RobustScaler + PCA on training set ONLY
    │
    ▼
preprocessor.transform_df()          ← Step 5: Transform both train & test into PCA feature space
    │                                            RobustScaler → PCA(whiten=True)
    ├── X_train  (float32 array)
    └── X_test   (float32 array)
    │
    ├──▶ NegativeSelectionDetector.fit(X_train_normal)   ← Step 6a: Train NSA
    │        Only BENIGN rows (y_train == 0) are used
    │
    └──▶ IsolationForestDetector.fit(X_train)            ← Step 6b: Train IsoForest
             All rows (semi-supervised)
    │
    ▼
evaluate_model() on X_test           ← Step 7: F1, Precision, Recall, ROC-AUC
    │
    ▼
nsa.save()  iso.save()  preprocessor.save()  ← Step 8: Persist .pkl artefacts
    │                                                     to app/artefacts/
    ▼
last_train_result.json               ← Step 9: Dashboard reads this on reload
_state["status"] = "active"
```

### 3.3 CIC-IDS-2017 Preprocessing — `app/core/preprocessor.py`

| Step | Action |
|------|--------|
| Load | Read CSV/Parquet; strip column name whitespace |
| Label encode | `BENIGN` → 0, all attacks → 1; map to `attack_category` |
| Drop metadata | Remove `Flow ID`, `Source IP`, `Destination IP`, `Timestamp` |
| Dedup columns | Drop second occurrence of `Fwd Header Length` |
| Fix quality | Replace `±Inf` → NaN → 0; clip to `±1e12` |
| Select numeric | Drop any remaining non-numeric columns |
| Scale | `RobustScaler` reduces outlier impact using median/IQR |
| Reduce dimensions | `PCA(whiten=True)` projects features into balanced PCA space |

### 3.4 NSA V-Detector Training — `app/models/nsa.py`

The Negative Selection Algorithm mimics thymus T-cell education:

```
X_train_normal  (BENIGN samples only)
    │
    ▼
Build self-reference set (cap at 5,000 points via random sample)
    │
    ▼
Auto-calibrate thresholds from benign PCA-space distances
    │   r   = high-percentile self-distance threshold
    │   r_s = high-percentile nearest-neighbour self-tolerance margin
    │
    ▼
KMeans(50 clusters) on self → cluster centroids
    │
    ▼
Candidate generation loop (default max_attempts = 30,000):
    │
    ├── Phase 1 (first half of detector target):
    │       candidate = centroid + Normal(0, r×3.0)   [Smart sampling]
    │
    └── Phase 2 (remaining detector target):
            candidate = self_point + Normal(0, r×1.5) [Boundary mutation]
            (no [0,1] clipping; candidates live in PCA space)
    │
    ▼
Negative Selection Filter:
    dist_to_nearest_self < r_s  →  REJECT  (reacts to self → clonal deletion)
    dist_to_nearest_self ≥ r_s  →  ACCEPT  (mature detector)
    │
    ▼
V-Detector radius = dist_to_nearest_self − r_s
    (variable radius gives multi-scale coverage of non-self space)
    │
    ▼
Inter-detector spacing check → reject candidates too close to existing detectors
    │
    ▼
Mature detector repertoire: up to 1,000 V-detectors by API default
Aging counters initialised (match_counts, idle_batches)
```

---

## Phase 4 — Batch Detection (Offline CSV Analysis)

```
User uploads network log CSV
Browser → POST /api/detect  (multipart/form-data)
        ← { message: "Detection started", status: "running" }
```

```
dataset_bytes
    │
    ▼
_build_engine()                      ← Load NSA/IsoForest + preprocessor from .pkl
    │
    ▼
DetectionEngine.detect_from_csv()    ← app/core/detection.py
    │
    ▼
preprocessor.transform()             ← Clean + transform using FITTED scaler/PCA (no refit)
    │   Preserves: Destination Port, Protocol, attack_category for heuristics
    ▼
model.predict_with_details(X_scaled) ← NSA or IsoForest inference
    │
    ├── NSA: Detector match  →  sample inside any V-detector sphere?
    │         Self-gap check →  dist_to_self > r  (innate immune fallback)
    │         Label = 1 if EITHER is true
    │
    └── IsoForest: sklearn anomaly_score < threshold → label = 1
    │
    ▼
_build_result()                      ← For each anomalous sample:
    │   severity_from_score()  →  critical / high / medium / low
    │   _infer_attack_type()   →  2-stage classifier:
    │       Stage 1: known label (DoS, DDoS, Probe, Brute Force, Web Attack…)
    │       Stage 2: flow-feature heuristics (12 rules, rule order matters)
    │       Fallback: Zero-Day Candidate (novelty_score ≥ 0.65)
    │   Build AlertRecord (alert_id, timestamp, src_ip, dst_ip, severity…)
    │
    ▼
_state["alerts"].extend(alerts)      ← Merge into in-memory alert log
AlertDB records written to SQLite    ← Persistent storage
    │
    ▼
GET /api/detect/result               ← Frontend retrieves final summary
Dashboard / Alerts page updated
```

---

## Phase 5 — Live Packet Capture & Real-Time Detection

This is the **streaming mode** — packets are sniffed, assembled into flows, scored, and pushed to authenticated browser clients over WebSocket.

### 5.1 Start Capture

```
Browser → POST /api/capture/start?interface=eth0
        ← { status: "capturing" }
```

Prerequisites: `models_ready()` must be true (artefacts exist on disk), and the request must include a valid JWT.

### 5.2 Packet → Flow → Feature → Alert Pipeline

```
Network Interface (raw socket)
    │
    ▼ Scapy sniff() — background thread ("pkt-sniffer")
    │
    ▼
FlowAggregator.ingest(raw_pkt)       ← app/core/capture.py
    │   Parse IP/TCP/UDP headers → PacketRecord
    │   Group by 5-tuple: (src_ip, dst_ip, src_port, dst_port, proto)
    │   Bidirectional: fwd packet if fid matches, bwd if reverse matches
    │
    ▼  Flow completion triggers (any of):
    │   • TCP FIN / RST flag seen
    │   • Idle > 30 seconds (reaper thread every 5 s)
    │   • Accumulated > 1,000 packets
    │
    ▼
FlowFeatureExtractor.extract(flow)   ← Computes all 77 CIC-IDS-2017 features:
    │   Packet length stats (mean, std, min, max)
    │   IAT (inter-arrival times) — forward, backward, combined
    │   TCP flag counts (SYN, ACK, FIN, RST, PSH, URG, CWE, ECE)
    │   Byte/packet rates (Flow Bytes/s, Flow Packets/s)
    │   Active / Idle periods
    │   Window sizes, header lengths, subflow stats
    │   + _src_ip, _dst_ip, _src_port, _dst_port, _protocol metadata
    │
    ▼
on_flow() callback (capture router)
    │   Pop metadata keys → meta dict
    │   DetectionEngine.detect_sample(features)  ← same engine as batch mode
    │
    ▼
Result → update _state counters
    │   Write RawFlowDB to SQLite
    │   If anomaly: write AlertDB, append to _state["alerts"]
    │   Update chart ring buffer (60-point sliding window)
    │
    ▼
asyncio.run_coroutine_threadsafe(
    _broadcast_live_update(), loop
)
    │
    ▼  WebSocket push to all connected browsers
WS /ws/live?token=<jwt>  →  { type: "flow", data: { anomalies_found, alerts, chart_... } }
    │
    ▼
React Dashboard (LiveCapturePage / Dashboard.jsx)
    WebSocket handler updates state → chart re-renders, alert table appends
```

### 5.3 WebSocket Protocol

| Message Type | Direction | Payload |
|---|---|---|
| `snapshot` | Server → Client | Full current state on connect |
| `flow` | Server → Client | Per-flow detection result + chart delta |
| `ping` | Server → Client | Keepalive (every 30 s timeout) |
| `ping` | Client → Server | Client keepalive |
| `pong` | Server → Client | Reply to client ping |

---

## Phase 6 — Alert Management & Firewall Response

### Alert Lifecycle

```
AlertRecord generated by DetectionEngine
    │
    ├── Stored in _state["alerts"]  (in-memory, lost on restart)
    └── Stored in AlertDB (SQLite)  (persistent)
    │
    ▼
GET /api/alerts          ← Alerts page fetches paginated list
PATCH /api/alerts/{id}   ← Analyst marks as false positive
GET /api/alerts/export.csv ← Analyst exports CSV with risk_score, repeat counts, recommended_action
    │
    ▼
User reviews alert → clicks "Block IP"
    │
    ▼
POST /api/firewall/block  { ip: "x.x.x.x" }
    │
    ▼
PowerShell: New-NetFirewallRule  (Windows Firewall inbound block)
    │
    ▼
_blocked_ips dict updated + BlockedIPDB written to SQLite
GET /api/firewall/blocked ← Firewall management page lists active blocks
```

---

## Phase 7 — Dashboard & Settings

### Dashboard Data Sources (`app/routers/dashboard.py`)

| Endpoint | Data |
|---|---|
| `GET /api/system/status` | CPU, RAM, uptime, model status |
| `GET /api/dashboard/stats` | Total alerts, anomaly rate, severity breakdown |
| `GET /api/model/summary` | NSA detector count, radius stats, IsoForest contamination |
| `GET /health` | Simple liveness probe |

### Settings (`PATCH /api/settings`)

- Switch active model between `nsa` and `isolation_forest`
- Updates `_state["active_model"]`; next detection call uses the new model

---

## Shared Application State — `app/state.py`

All routers share a single in-memory dict `_state`:

```python
_state = {
    "status":           "idle | learning | active | error",
    "training_logs":    [],          # streamed to frontend
    "alerts":           [],          # in-memory alert log
    "active_model":     "nsa",       # or "isolation_forest"
    "packet_count":     0,
    "anomaly_count":    0,
    "capture_active":   False,
    "sniffer":          None,        # PacketSniffer instance
    "ws_clients":       [],          # active WebSocket connections
    "chart_normal":     [0]*60,      # 60-point ring buffer
    "chart_anomaly":    [0]*60,
    "flows_completed":  0,
    "detect_status":    "idle | running | done | error",
    "last_detect_result": None,
}
```

`_build_engine()` constructs a `DetectionEngine` on demand by loading the `.pkl` artefacts from disk.

---

## Persisted Artefacts — `app/artefacts/`

| File | Contents |
|---|---|
| `nsa_model.pkl` | Fitted `NegativeSelectionDetector` (detectors, radii, self-reference) |
| `iso_model.pkl` | Fitted `IsolationForestDetector` |
| `preprocessor.pkl` | Fitted `CICIDSPreprocessor` (RobustScaler + PCA + feature_columns_) |
| `last_train_result.json` | Training metrics (F1, Precision, Recall, duration) |

---

## Database Schema — SQLite (`app/core/database.py`)

| Table | Purpose |
|---|---|
| `users` | id, username, password, role |
| `alerts` | Full AlertRecord + raw_features JSON |
| `blocked_ips` | ip, blocked_at, reason, rule_name |
| `raw_flows` | Lightweight flow log (timestamp, src/dst IP/port, bytes/s) |

---

## Complete End-to-End Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│  BROWSER (React + Vite, port 5173 dev / static in prod)            │
│  Login → Dashboard → Train → Detect → Live Capture → Alerts        │
└────────────────────────┬────────────────────────────────────────────┘
                         │ HTTP / WebSocket
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  FASTAPI BACKEND  (port 8000)                                       │
│                                                                     │
│  /api/auth       → Auth router     → SQLite users table            │
│  /api/train      → Training router → TrainingPipeline              │
│                                         └→ Preprocessor (fit)      │
│                                         └→ NSA.fit (BENIGN only)   │
│                                         └→ IsoForest.fit (all)     │
│                                         └→ Save .pkl artefacts     │
│                                                                     │
│  /api/detect     → Detection router → DetectionEngine              │
│                                         └→ Preprocessor (transform)│
│                                         └→ NSA / IsoForest predict │
│                                         └→ _infer_attack_type()    │
│                                         └→ AlertDB (SQLite)        │
│                                                                     │
│  /api/capture    → Capture router                                  │
│    /start           └→ PacketSniffer (Scapy, background thread)    │
│                           └→ FlowAggregator (5-tuple grouping)     │
│                                └→ FlowFeatureExtractor (77 feats)  │
│                                     └→ DetectionEngine.detect_sample│
│                                          └→ WS broadcast           │
│  /ws/live        → Authenticated WebSocket → Browser live updates  │
│                                                                     │
│  /api/alerts     → Alert CRUD + false-positive marking             │
│  /api/firewall   → Windows Firewall block/unblock (PowerShell)     │
│  /api/dashboard  → System stats, model summary                     │
└─────────────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STORAGE LAYER                                                      │
│  SQLite DB  ─  users / alerts / blocked_ips / raw_flows            │
│  app/artefacts/  ─  nsa_model.pkl / iso_model.pkl / preprocessor   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Train/test split **before** fitting the scaler/PCA | Prevents data leakage — test set statistics never influence preprocessing |
| RobustScaler + PCA whitening | Reduces outlier compression and keeps NSA distances meaningful in lower-dimensional feature space |
| Dynamic NSA thresholds | Calibrates `r` and `r_s` from benign PCA-space distances instead of hard-coded `[0,1]` assumptions |
| NSA trains on **BENIGN only** | Mirrors biological negative selection — detectors are educated against self |
| IsoForest trains on **all** samples | Semi-supervised baseline for comparison |
| Variable-radius V-detectors | Detectors automatically expand to cover as much non-self space as possible |
| Self-gap fallback (innate immune) | Catches anomalies in regions not yet covered by any detector |
| Detector aging (`idle_batches`) | Models finite T-cell lifespan; stale detectors can be refreshed |
| Feature extraction mimics CICFlowMeter | Live capture produces the exact same 77 features as the training dataset |
| Authenticated WebSocket + HTTP polling fallback | Ensures real-time updates while requiring valid user access |
| Windows Firewall via PowerShell | Allows one-click IP blocking directly from the dashboard |
