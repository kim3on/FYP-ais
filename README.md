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
