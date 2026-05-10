# GEMINI.md — AIS-Detect Context

This file provides foundational context and instructions for AI agents working on the **AIS-Detect** project.

## Project Overview
**AIS-Detect** is a high-performance network anomaly detection system inspired by biological Artificial Immune Systems (AIS). It uses the **Negative Selection Algorithm (NSA)** with a **True V-Detector** architecture to identify network attacks (e.g., DoS, DDoS, Botnets) within the CIC-IDS-2017 dataset.

### Core Stack
- **Backend:** FastAPI (Python 3.12+), SQLAlchemy (SQLite), Scapy (Packet Sniffing).
- **Frontend:** React 19 (Vite), Chart.js (Real-time visualization), Tailwind CSS (Aesthetic: Cyber-Defense/Rosé Pine).
- **ML:** Scikit-learn (Isolation Forest baseline), Pandas, NumPy.

### Key Operating Modes
1.  **Training:** Offline learning from CIC-IDS-2017 CSV/Parquet files.
2.  **Batch Detection:** High-speed anomaly analysis of uploaded historical logs.
3.  **Live Detection:** Real-time packet capture, flow aggregation, and WebSocket-based alert streaming.

---

## Building and Running

### 1. Backend Setup (Windows/PowerShell)
```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
*Note: Live capture (`/api/capture/*`) requires Administrator privileges and Npcap installed.*

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev   # Development (port 5173)
npm run build # Production (outputs to app/static_react/)
```

### 3. Running Tests
```powershell
cd "validate and test"
python test_backend.py # Backend & Model Tests
python validate_ml.py  # ML Statistical Integrity Auditor
```

---

## Architecture & Data Flow
- **`app/main.py`:** Application entry point and router registration.
- **`app/core/`:** Contains the "Brain" (detection, pipeline, preprocessor).
- **`app/models/`:** Implements `nsa.py` (True V-Detector) and `isolation_forest.py`.
- **`app/routers/`:** REST API endpoints (Auth, Training, Detection, Alerts, etc.).
- **`app/state.py`:** Shared in-memory application state (`_state`).
- **`app/artefacts/`:** Stores persistent ML models (`.pkl`) and the SQLite database.

---

## Development Conventions

### Security Mandates
- **Auth:** All non-health endpoints require JWT authentication. Use `Depends(get_current_user)`.
- **Passwords:** NEVER store or log plaintext passwords. Use `bcrypt` hashing via `passlib`.
- **WebSockets:** Protect `/ws/live` by verifying tokens passed in the query string.

### Machine Learning Standards
- **Leakage Prevention:** Always split data *before* fitting scalers or models.
- **NSA Training:** The Negative Selection Algorithm must train ONLY on "BENIGN" (Self) samples.
- **Feature Extraction:** Maintain parity between the 77-feature extraction in `capture.py` and the `preprocessor.py` used for training.

### UI/UX Aesthetic
- **Theme:** "Cyber-Defense" / Rosé Pine.
- **Visuals:** High contrast, rounded bento-style cards, real-time pulse indicators for system status.
- **Feedback:** Every async action (Training, Detection) must provide live log streaming to the UI.

---

## Key Files for Reference
- `DATAFLOW.md`: Detailed end-to-end technical walkthrough.
- `README.md`: General overview and getting started guide.
- `analysis/`: Directory containing deep-dive audits (Security, UI/UX, ML).
- `app/models/db_models.py`: SQLAlchemy database schema.
