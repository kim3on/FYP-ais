# FYP Final Report Update Draft Based on Current AIS-Detect Codebase

This draft rewrites the outdated parts of the January 2026 FYP Final Report so the report matches the current AIS-Detect codebase. The old report was written before the current FastAPI, React, CIC-IDS-2017, JWT, live capture, and benign-only AIS pipeline work. Several items that were previously described as future work are now implemented.

Use this document as source material for updating the PDF sections, especially the abstract, methodology, implementation, evaluation, database design, prototype screenshots, conclusion, and future work.

## 1. Updated Abstract

Traditional Network Intrusion Detection Systems (NIDS), such as Snort and Security Onion, are effective at detecting known attacks through signatures, rules, and protocol analysis. However, these approaches are limited when facing unknown or zero-day attacks that do not match existing detection patterns. This project addresses that gap by developing AIS-Detect, a web-based network anomaly detection prototype inspired by the human immune system.

AIS-Detect uses an Artificial Immune System (AIS) based on the Negative Selection Algorithm (NSA), specifically a V-Detector design, to learn a profile of normal or "self" network traffic and identify flows that deviate from that profile. The system is implemented using a FastAPI backend and a React/Vite frontend dashboard. The backend supports model training, batch detection, live packet capture, alert storage, authentication, runtime settings, user management, and analytical alert export.

The current system uses CIC-IDS-2017 as the main live-compatible dataset profile because it matches CICFlowMeter-style flow features used during live packet capture. NSL-KDD is still supported, but only as an offline batch benchmark because its feature schema is not compatible with live CICFlowMeter features. The machine learning pipeline follows a strict benign-only calibration approach: RobustScaler, PCA whitening, NSA detectors, Self-Boundary models, Isolation Forest baseline, and anomaly thresholds are fitted or calibrated using BENIGN training/calibration rows only. Attack labels are used only after prediction for verification metrics such as recall, false negative rate, false positive rate, precision, and F1.

The final system demonstrates that a bio-inspired anomaly detection approach can be integrated into a lightweight academic web platform. It is suitable as an FYP research prototype for demonstrating AIS-based anomaly detection, live monitoring, and analyst-facing alert review. However, it should not be described as a production SOC-ready system without further hardening, multi-sensor deployment design, stronger operational validation, and security improvements.

## 2. Main Corrections Required

The current report must be updated in the following areas:

- Replace NSL-KDD as the main dataset with CIC-IDS-2017 for the live-compatible workflow.
- Describe NSL-KDD only as an offline batch benchmark profile.
- Replace any Flask references with FastAPI.
- Move FastAPI integration, WebSocket live updates, live capture, confidence scoring, export, and detector aging out of Future Work because they are now implemented.
- Replace generic NSA wording with the actual V-Detector NSA in PCA-whitened space.
- Replace accuracy-first evaluation with benign-only calibration metrics and post-run labelled verification.
- Replace the old ERD with the actual SQLite tables.
- Remove claims that Account supports password update or 2FA/MFA, because those are not implemented.
- Avoid claiming production SOC readiness. The system is an academic prototype.

## 3. Dataset Scope Update

The old report says NSL-KDD is the main validation dataset. The current implementation separates dataset profiles:

- `cicids2017`: main dataset profile, live-compatible, supports CSV/Parquet CICFlowMeter-style flow features.
- `nsl_kdd`: offline batch benchmark only, supports CSV with NSL-KDD headers.

Implementation:

```python
# app/core/datasets.py
DATASET_CICIDS2017 = "cicids2017"
DATASET_NSL_KDD = "nsl_kdd"
SUPPORTED_DATASETS = {DATASET_CICIDS2017, DATASET_NSL_KDD}

def normalize_dataset_type(dataset_type: str | None) -> str:
    value = (dataset_type or DATASET_CICIDS2017).strip().lower().replace("-", "_")
    aliases = {
        "cicids": DATASET_CICIDS2017,
        "cic_ids_2017": DATASET_CICIDS2017,
        "cicids_2017": DATASET_CICIDS2017,
        "nslkdd": DATASET_NSL_KDD,
        "nsl_kdd": DATASET_NSL_KDD,
    }
    value = aliases.get(value, value)
    if value not in SUPPORTED_DATASETS:
        raise ValueError(...)
    return value
```

Artifact separation:

```python
# app/core/datasets.py
def artifact_paths(dataset_type: str | None = DATASET_CICIDS2017) -> ArtifactPaths:
    dataset = normalize_dataset_type(dataset_type)
    root = os.path.join(ARTEFACT_DIR, dataset)
    return ArtifactPaths(
        root=root,
        nsa=os.path.join(root, "nsa_model.pkl"),
        iso=os.path.join(root, "iso_model.pkl"),
        preprocessor=os.path.join(root, "preprocessor.pkl"),
        self_boundary=os.path.join(root, "self_boundary.pkl"),
        pca_self_boundary=os.path.join(root, "pca_self_boundary.pkl"),
        results=os.path.join(root, "last_train_result.json"),
    )
```

Explanation:

The current design prevents incompatible feature schemas from being mixed. CIC-IDS-2017 flow features are compatible with live capture because they follow CICFlowMeter-style fields. NSL-KDD contains a different set of symbolic and numeric features, so it cannot be used for live packet capture.

Recommended report wording:

> AIS-Detect uses CIC-IDS-2017 as the main dataset profile for live-compatible flow-based intrusion detection. NSL-KDD is supported as a separate offline benchmark profile only, because its feature schema is different from CICFlowMeter features and cannot be used for live packet capture.

## 4. Current Machine Learning Methodology

### 4.1 Strict Benign-Only Training

The old report says the system handles dirty traffic where hidden attacks pollute training data. The current implementation should be described more precisely. It does not automatically remove unknown attacks from unlabeled dirty data. Instead, it uses the dataset label column to select BENIGN rows and then trains/calibrates the unsupervised model only on those BENIGN rows.

Implementation:

```python
# app/core/pipeline.py
df_raw, y_all = preprocessor._encode_labels(df_raw, label_col)

benign_mask = y_all == 0
df_benign = df_raw.loc[benign_mask].reset_index(drop=True)
df_attack_raw = df_raw.loc[~benign_mask].reset_index(drop=True)
```

```python
# app/core/pipeline.py
df_train_raw, df_holdout_raw = train_test_split(
    df_benign,
    test_size=holdout_size,
    random_state=self.random_state,
    shuffle=True,
)

df_cal_raw, df_test_raw = train_test_split(
    df_holdout_raw,
    test_size=0.5,
    random_state=self.random_state,
    shuffle=True,
)
```

Explanation:

Labels are used only to select BENIGN rows for self-profile learning and to perform post-run verification. Attack rows are not used to fit the scaler, PCA, NSA detectors, Self-Boundary models, score scales, fusion weights, or thresholds.

Recommended report wording:

> The training phase follows a strict benign-only self-profile approach. BENIGN rows are split into training, calibration, and test subsets. The model learns the normal self-space only from BENIGN rows. Attack labels are not used to tune the anomaly detector; they are used only after prediction to verify how well the unsupervised detector catches labelled attacks.

### 4.2 Leakage-Free Preprocessing

RobustScaler and PCA are fitted only on BENIGN training rows.

Implementation:

```python
# app/core/pipeline.py
preprocessor.fit(df_train_raw)

X_train, _ = preprocessor.transform_df(df_train_raw)
X_cal, _ = preprocessor.transform_df(df_cal_raw)
X_test, df_test_meta = preprocessor.transform_df(df_test_raw)
```

```python
# app/core/preprocessor.py
self.scaler_ = RobustScaler()
X_scaled = self.scaler_.fit_transform(X)

if self.n_pca_components:
    from sklearn.decomposition import PCA
    self.pca_ = PCA(
        n_components=self.n_pca_components,
        random_state=42,
        svd_solver='full',
        whiten=True,
    )
    self.pca_.fit(X_scaled)
```

Explanation:

This prevents data leakage. Calibration, test, and detection rows are transformed using the fitted scaler and PCA, but they do not fit those transformers.

Recommended report wording:

> To prevent data leakage, AIS-Detect fits RobustScaler and PCA only on the BENIGN training split. Calibration, test, and detection data are transformed using the saved fitted transformer. PCA is configured with whitening so the NSA detector geometry operates in PCA-whitened feature space.

## 5. NSA Radius Parameters: Important Report Correction

This section must be added because the old UI/report wording can make `r` and `r_s` look like normal user-tuned controls. In the current pipeline, they are mostly fitted values derived from benign PCA geometry.

### 5.1 Why `r` and `r_s` Are Misleading as Manual Sliders

The backend training route still accepts `r` and `r_s`:

```python
# app/routers/training.py
async def train(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    r:              float = 0.3,
    r_s:            float | None = None,
    max_detectors:  int   = 3000,
    max_attempts:   int   = 100_000,
    contamination:  float = 0.05,
    test_size:      float = 0.2,
    n_pca_components: int | None = 25,
    target_fpr:     float = 0.05,
    benign_row_limit: int | None = 20_000,
    dataset_type:    str = DATASET_CICIDS2017,
):
```

However, the NSA model is created with `auto_threshold=True` by default:

```python
# app/models/nsa.py
def __init__(
    self,
    r: float = 0.15,
    r_s: float | None = None,
    max_detectors: int = 3000,
    max_attempts: int = 100_000,
    random_state: int = 42,
    confidence_threshold: float = 0.05,
    auto_threshold: bool = True,
):
    self.r = r
    self.r_s = r_s if r_s is not None else min(r * 0.1, 0.05)
    self.auto_threshold = auto_threshold
```

During fitting, the model recomputes both values from the BENIGN PCA training data:

```python
# app/models/nsa.py
if self.auto_threshold:
    ...
    # Dynamic r (Self-Gap Threshold): 99th percentile of nearest-neighbour
    # distances.
    self.r = max(float(np.percentile(nn_dists, 99.0)), 0.05)

    # Dynamic r_s (Thymus Stringency): materially smaller than r.
    # Uses p30 nearest-neighbour distance.
    self.r_s = max(float(np.percentile(nn_dists, 30.0)), 0.01)
```

The fitted values are saved into the model metadata:

```python
# app/models/nsa.py
self.meta_ = {
    "r": self.r,
    "r_s": self.r_s,
    "auto_threshold": self.auto_threshold,
    "r_fitted": round(self.r, 6),
    "r_s_fitted": round(self.r_s, 6),
}
```

Explanation:

In the current pipeline:

- `r` becomes the 99th percentile nearest-neighbour distance from benign PCA-space training data.
- `r_s` becomes the 30th percentile nearest-neighbour distance from benign PCA-space training data.
- This means manual values sent into training are not reliable user-facing controls when `auto_threshold=True`.
- The academically stronger explanation is that AIS-Detect derives these values from benign training geometry to avoid arbitrary radius selection after PCA whitening.

### 5.2 Current UI Design Already Matches This Recommendation

The current Train & Detect page does not expose normal `r` and `r_s` sliders. It sends detector count, target FPR, dataset profile, and optional BENIGN row limit:

```jsx
// frontend/src/pages/TrainDetect.jsx
const data = await startTraining(file, {
  max_detectors: nDetectors,
  target_fpr: 0.05,
  dataset_type: datasetType,
  ...(benignRowLimit ? { benign_row_limit: benignRowLimit } : {}),
});
```

The frontend shows the radius values after training as fitted values:

```jsx
// frontend/src/pages/TrainDetect.jsx
const fittedR = trainResult.nsa_summary?.r_fitted ?? trainResult.nsa_summary?.r;
const fittedRS = trainResult.nsa_summary?.r_s_fitted ?? trainResult.nsa_summary?.r_s;

const detailMetrics = [
  ['Fitted Self-Gap Radius', fittedR != null ? Number(fittedR).toFixed(4) : '-', 'var(--accent)'],
  ['Fitted Detector Tolerance', fittedRS != null ? Number(fittedRS).toFixed(4) : '-', 'var(--accent)'],
];
```

Recommended report wording:

> AIS-Detect does not manually tune NSA radius values in the main system because PCA-whitened feature space changes by dataset. Instead, the system derives the self-gap radius (`r`) and detector self-tolerance (`r_s`) from benign training geometry. The fitted self-gap radius is calculated from the 99th percentile nearest-neighbour distance, while the fitted detector tolerance is calculated from the 30th percentile nearest-neighbour distance. These values are displayed after training as fitted model metadata rather than exposed as normal user-adjustable controls.

Recommended UI/prototype wording:

> The training interface keeps the normal user controls limited to dataset profile, dataset upload, maximum detector count, and BENIGN row limit. The NSA radius parameters are not presented as ordinary sliders because the backend derives them from the PCA-space self profile. After training, the system displays `Fitted Self-Gap Radius` and `Fitted Detector Tolerance` for transparency.

Suggested FYP defense answer:

> We do not manually tune NSA radius values in the main system because PCA-whitened feature space changes by dataset. The system derives `r` and `r_s` from benign training geometry to avoid arbitrary thresholds.

## 6. Current NSA V-Detector Design

The old report talks about spherical antibodies in a 2D visualization. That should be treated as a teaching diagram only. The real implementation operates in high-dimensional PCA-whitened space.

Implementation:

```python
# app/models/nsa.py
# PCA-whitened space is unbounded; the expanded quantile envelope targets
# benign tails without falling back to invalid [0, 1] clipping.
q_low = np.quantile(ref, 0.01, axis=0).astype(np.float32)
q_high = np.quantile(ref, 0.99, axis=0).astype(np.float32)
span = np.maximum(q_high - q_low, 1e-3).astype(np.float32)
envelope_low = q_low - (0.35 * span)
envelope_high = q_high + (0.35 * span)
```

```python
# app/models/nsa.py
if min_sq < r_s_sq_thresh:
    rejected += 1
else:
    min_dist_norm = float(np.sqrt(max(min_sq, 0.0))) / scale
    det_radius = min_dist_norm - self.r_s

    if det_radius > 0:
        detectors[n_detectors] = candidate
        radii[n_detectors] = det_radius
        n_detectors += 1
```

Explanation:

Each mature detector has a variable radius. Candidates that are too close to self traffic are rejected. Accepted detectors occupy non-self regions outside the self-tolerance margin. The model does not assume values are bounded to `[0, 1]`, because PCA-whitened values are unbounded.

Recommended report wording:

> The current NSA model implements a V-Detector variant. Instead of using fixed-radius detectors in a normalized `[0,1]` space, detectors are generated in PCA-whitened feature space. A detector candidate is rejected if it reacts to self traffic. If it survives, it becomes a mature detector with a variable radius based on its distance from the nearest self reference minus the self-tolerance margin.

## 7. Final AIS Decision Logic

The final AIS decision is not only a simple distance threshold. It combines detector evidence, self-gap evidence, and fused AIS scoring with PCA Self-Boundary.

Implementation:

```python
# app/models/nsa.py
def predict_fused(
    self,
    X: np.ndarray,
    self_boundary_scores: np.ndarray | None = None,
    alert_threshold: float | None = None,
):
    raw_scores = self.fused_scores(X, self_boundary_scores)
    threshold = self._scaled_threshold(self.fusion_threshold_, alert_threshold)
    detector_matches, detector_scores = self._check_detector_match(X, update_aging=False)
    detector_matches = self._runtime_detector_matches(
        detector_matches,
        detector_scores,
        alert_threshold,
    )
    labels = ((raw_scores > threshold) | detector_matches).astype(int)
    return labels, scores, raw_scores
```

```python
# app/models/nsa.py
return {
    "v_detector_match": detector_matches.astype(bool),
    "self_gap_match": self_gap_matches,
    "nsa_score_match": (nsa_scores > nsa_threshold).astype(bool),
    "fusion_score_match": (fused_scores > fusion_threshold).astype(bool),
}
```

Explanation:

Mature V-detector hits remain primary anomaly evidence. The fusion score adds additional calibrated evidence from NSA score components and PCA-space Self-Boundary. Self-gap evidence is used for samples that are far away from known self traffic.

Recommended report wording:

> The final AIS decision uses a two-layer anomaly mechanism. Mature V-detector matches are treated as primary anomaly evidence. In addition, the model calculates self-gap and fused AIS scores. The fused score combines NSA distance, density, detector-depth, and PCA Self-Boundary evidence. A flow is flagged when it matches a mature V-detector or exceeds the calibrated fused AIS threshold.

## 8. Self-Boundary and Score Fusion

The current system includes Self-Boundary detection. This should be added to the methodology and implementation chapter.

Implementation:

```python
# app/core/pipeline.py
raw_sb = SelfBoundaryDetector(
    z_threshold=2.0,
    min_violations_ratio=0.15,
)
raw_sb.fit(df_train_features, preprocessor.feature_columns_)

pca_sb = SelfBoundaryDetector(
    z_threshold=2.0,
    min_violations_ratio=0.15,
)
pca_sb.fit(X_train_pca_df, pca_feature_columns)
```

```python
# app/core/pipeline.py
fusion_calibration = nsa.calibrate_fusion(
    X_cal,
    self_boundary_scores=pca_sb_cal_scores,
    target_fpr=self.target_fpr,
)
```

Explanation:

There are two Self-Boundary models:

- Raw-feature Self-Boundary: used for human-readable evidence in alerts.
- PCA-space Self-Boundary: used in final fused AIS scoring.

Recommended report wording:

> AIS-Detect includes a Self-Boundary component to measure whether a flow violates learned benign feature boundaries. The raw-feature Self-Boundary model provides analyst-facing evidence, while the PCA-space Self-Boundary model contributes to final AIS score fusion. Both are trained and calibrated using BENIGN rows only.

## 9. Updated Evaluation Section

The old report treats accuracy, precision, and recall as the main evaluation. This must be changed because the current training pipeline is unsupervised and benign-only.

Implementation:

```python
# app/core/pipeline.py
y_test = np.zeros(len(X_test), dtype=int)
nsa_result = evaluate_model(y_test, nsa_labels, "AIS (NSA)", df_test_meta)
fused_result = evaluate_model(
    y_test,
    fused_labels,
    "AIS (Fused NSA + Self-Boundary)",
    df_test_meta,
)
```

```python
# app/core/pipeline.py
nsa_eval["training_metric_note"] = (
    "Benign-only training validation has no attack class; precision, recall, F1, "
    "TPR, and FNR are intentionally not reported here."
)
for attack_metric in ("precision", "recall", "f1", "false_negative_rate", "detection_rate", "true_positive_rate"):
    nsa_eval[attack_metric] = None
```

Attack labels are used only after prediction:

```python
# app/core/pipeline.py
labelled_metrics["verification_note"] = (
    "Attack labels are used only after unsupervised prediction to report "
    "recall, FNR, FPR, precision, and threshold tradeoffs. They do not "
    "modify saved model artifacts or thresholds."
)
```

Recommended report wording:

> Because AIS-Detect trains on BENIGN traffic only, training success is not measured primarily using attack-class accuracy. Instead, the training result reports benign false-positive behaviour, self-intrusion rate, normal pass rate, calibration reliability, and unsupervised separation indicators. If labelled attack rows are present, the system performs post-run labelled verification after prediction to report recall, FNR, FPR, precision, and F1. These labelled metrics are verification-only and do not tune the saved model.

## 10. System Architecture Update

FastAPI integration, WebSocket updates, live capture, and export should no longer be listed as future work. They are implemented.

Current architecture:

```text
React/Vite frontend
    |
    | HTTP REST + JWT
    | WebSocket /ws/live?token=<jwt>
    v
FastAPI backend
    |
    | training / detection / capture / alerts / settings / users
    v
AIS detection engine
    |
    | RobustScaler + PCA(whiten=True)
    | NSA V-Detector + PCA Self-Boundary
    | Isolation Forest baseline
    v
SQLite persistence
```

Implementation:

```python
# app/main.py
app = FastAPI(
    title="AIS-Detect API",
    description="Web-Based Network Anomaly Detection using Artificial Immune Systems",
    version="4.0.0",
)

app.include_router(auth.router)
app.include_router(training.router)
app.include_router(detection.router)
app.include_router(alerts.router)
app.include_router(capture.router)
app.include_router(dashboard.router)
app.include_router(firewall.router)
app.include_router(users.router)
```

Frontend routes:

```jsx
// frontend/src/App.jsx
<Routes>
  <Route path="/login" element={<Login />} />
  <Route path="/" element={<Layout />}>
    <Route index element={<Dashboard />} />
    <Route path="train" element={<TrainDetect />} />
    <Route path="alerts" element={<Alerts />} />
    <Route path="settings" element={<Settings />} />
    <Route path="account" element={<Account />} />
    <Route path="users" element={<Users />} />
    <Route path="accessibility" element={<Accessibility />} />
  </Route>
</Routes>
```

Recommended report wording:

> The final implementation uses FastAPI as the backend API server and React/Vite as the frontend dashboard. FastAPI registers separate routers for authentication, training, detection, alerts, capture, dashboard settings, firewall actions, and user management. The React frontend is organized into operational pages for Dashboard, Train & Detect, Alerts, Settings, Accessibility, Account, and Users.

## 11. Authentication and Security Update

Implemented:

- bcrypt password hashes.
- signed JWT login.
- authenticated API routes.
- token-protected WebSocket.
- admin-only user management.

Implementation:

```python
# app/routers/auth.py
SECRET_KEY = os.getenv("AIS_SECRET_KEY") or _DEV_SECRET
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24
```

```python
# app/routers/auth.py
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode('utf-8'),
        hashed_password.encode('utf-8')
    )

def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')
```

```python
# app/routers/users.py
router = APIRouter(
    prefix="/api/users",
    tags=["users"],
    dependencies=[Depends(require_admin_user)]
)
```

WebSocket token check:

```python
# app/routers/capture.py
@router.websocket("/ws/live")
async def websocket_live(ws: WebSocket, token: Optional[str] = Query(None)):
    if not token:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        db = SessionLocal()
        try:
            get_user_from_token(token, db)
        finally:
            db.close()
    except HTTPException:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws.accept()
```

Security limitations:

- Development JWT secret is used if `AIS_SECRET_KEY` is not set.
- Default seeded accounts are used unless environment variables override them.
- CORS defaults to `*`.
- MFA/2FA is not implemented.
- The project is an academic prototype, not a production SOC platform.

Recommended report wording:

> AIS-Detect includes JWT-based authentication and bcrypt password hashing. Most API routes require a valid bearer token, and live WebSocket access requires a token in the connection query. User management is restricted to administrator users. However, deployment hardening is still required before public exposure, including setting `AIS_SECRET_KEY`, replacing default seeded passwords, restricting CORS origins, adding MFA, and using a production-grade deployment configuration.

## 12. Live Capture and Manual Flow Submission

Live capture is now implemented for the CIC-IDS-2017 profile.

Implementation:

```python
# app/routers/capture.py
@router.post("/api/capture/start")
async def start_capture(interface: Optional[str] = None, user=Depends(get_current_user)):
    if _state["capture_active"]:
        raise HTTPException(status_code=409, detail="Capture already running")

    if _state.get("active_dataset_type") != DATASET_CICIDS2017:
        raise HTTPException(
            status_code=400,
            detail="Live capture is CICIDS2017-only. NSL-KDD models are batch benchmark models and cannot score live CICFlowMeter features.",
        )
```

Manual flow submission:

```python
# app/routers/capture.py
@router.post("/api/capture/submit-flow")
async def submit_flow_file(
    file: UploadFile = File(...),
    limit: Optional[int] = 1000,
    user=Depends(get_current_user),
):
    """
    Submit an offline flow file for immediate scoring.

    CSV/Parquet files are treated as pre-extracted CICIDS-compatible flow rows.
    PCAP/PCAPNG files are converted through CICFlowMeter before scoring.
    """
```

PCAP conversion:

```python
# app/routers/capture.py
with PcapReader(str(source_path)) as reader:
    for packet in reader:
        if IP in packet and (TCP in packet or UDP in packet):
            session.process(packet)
session.flush_flows()
```

Recommended report wording:

> Live capture is implemented for the CIC-IDS-2017 profile. The backend uses a packet sniffer and CICFlowMeter-compatible flow conversion to transform packets into flow features before scoring them with the active detection engine. The dashboard also supports manual submission of CSV, Parquet, PCAP, and PCAPNG files. PCAP/PCAPNG files are converted into flow rows before detection.

Important limitation:

> Live capture requires administrator/root privileges, Scapy, and Npcap on Windows. It observes traffic only from the selected local interface. A cloud-hosted dashboard cannot directly capture traffic from a user laptop unless a local sensor forwards features or uploads files.

## 13. Alert Storage and Export

Implementation:

```python
# app/models/db_models.py
class AlertDB(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True)
    timestamp = Column(String)
    attack_type = Column(String)
    src_ip = Column(String)
    dst_ip = Column(String)
    dst_port = Column(Integer)
    protocol = Column(String)
    severity = Column(String)
    confidence = Column(Float)
    confidence_pct = Column(String)
    is_false_positive = Column(Boolean, default=False)
    is_zero_day = Column(Boolean, default=False)
    raw_features = Column(JSON, nullable=True)
```

Alert summary export:

```python
# app/routers/alerts.py
@router.get("/export.csv")
async def export_alerts_csv(
    from_: Optional[str] = Query(None, alias="from"),
    to: Optional[str] = None,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    include_false_positive: bool = True,
    zero_day_only: bool = False,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    _require_export_role(user)
```

Recommended report wording:

> Alerts are stored in SQLite with severity, confidence, attack-family attribution, false-positive status, zero-day status, endpoint metadata, and raw feature evidence. The system provides an alert summary CSV export containing report overview, severity summary, attack-family summary, top sources, top targets, repeated endpoint pairs, priority incidents, and action-code guidance.

## 14. Database Design Replacement

The old ERD does not match the current code. Replace it with these actual tables:

```text
users
  id
  username
  password
  role

user_profiles
  id
  user_id
  display_name
  email
  phone
  job_title
  soc_tier
  team
  shift
  timezone
  escalation_contact

alerts
  id
  alert_id
  timestamp
  attack_type
  src_ip
  dst_ip
  dst_port
  protocol
  severity
  confidence
  confidence_pct
  is_false_positive
  is_zero_day
  raw_features

blocked_ips
  ip
  blocked_at
  reason
  rule_name

raw_flows
  id
  timestamp
  src_ip
  dst_ip
  dst_port
  protocol
  flow_bytes_s
```

Recommended report wording:

> The implemented database uses SQLite through SQLAlchemy. It stores users, user profiles, alerts, firewall block records, and raw captured flow summaries. Model artifacts are not stored in the database; they are saved as dataset-specific files under the application artifact directory.

## 15. Runtime Settings

Implementation:

```python
# app/state.py
data = {
    "active_model": _state.get("active_model", "nsa"),
    "active_dataset_type": _state.get("active_dataset_type", DATASET_CICIDS2017),
    "threshold": float(_state.get("threshold", DEFAULT_ALERT_THRESHOLD)),
    "zero_day_threshold": float(_state.get("zero_day_threshold", DEFAULT_ZERO_DAY_THRESHOLD)),
}
```

```python
# app/routers/dashboard.py
@router.patch("/api/settings")
async def update_settings(settings: SettingsUpdate, user=Depends(get_current_user)):
    if settings.active_model is not None:
        if settings.active_model not in ("nsa", "isolation_forest"):
            raise HTTPException(status_code=400, detail="Invalid active_model")

    if settings.threshold is not None:
        threshold = float(settings.threshold)
        if not 0.10 <= threshold <= 0.90:
            raise HTTPException(status_code=400, detail="threshold must be between 0.10 and 0.90")

    if settings.zero_day_threshold is not None:
        zero_day_threshold = float(settings.zero_day_threshold)
        if not 0.30 <= zero_day_threshold <= 0.95:
            raise HTTPException(status_code=400, detail="zero_day_threshold must be between 0.30 and 0.95")
```

Recommended report wording:

> The Settings page allows the user to switch between the AIS/NSA engine and the Isolation Forest baseline, provided the selected engine has trained artifacts for the active dataset profile. Runtime alert and zero-day thresholds are validated by the backend and persisted in `runtime_settings.json`.

## 16. UI and Prototype Update

Current frontend routes:

- Login
- Dashboard
- Train & Detect
- Alerts
- Settings
- Accessibility & Help Centre
- Account
- Users

Important correction:

The old report says the Account page supports password updates and 2FA. Current code does not implement password update or MFA/2FA in the Account page. It supports profile/contact/session details only.

Implementation:

```jsx
// frontend/src/pages/Account.jsx
const PROFILE_FIELDS = [
  { key: 'display_name', label: 'Display Name' },
  { key: 'email', label: 'Email' },
  { key: 'phone', label: 'Phone' },
  { key: 'job_title', label: 'Job Title' },
  { key: 'soc_tier', label: 'SOC Tier' },
  { key: 'team', label: 'Team' },
  { key: 'shift', label: 'Shift' },
  { key: 'timezone', label: 'Timezone' },
  { key: 'escalation_contact', label: 'Escalation Contact' },
];
```

Recommended report wording:

> The Account page allows users to view their role, session context, and operational profile fields such as job title, SOC tier, team, shift, timezone, and escalation contact. Password update and MFA are not currently implemented and remain future enhancements.

## 17. Chapter 4 Replacement Structure

The current Chapter 4 is mostly a placeholder. Replace it with:

### 4.1 Introduction

Explain that this chapter presents the implemented AIS-Detect system, including backend integration, frontend dashboard, machine learning pipeline, live capture, authentication, database persistence, and evaluation.

### 4.2 System Integration

Discuss:

- FastAPI backend.
- React/Vite frontend.
- SQLite database.
- Dataset-specific artifacts.
- JWT authentication.
- WebSocket live updates.
- Scapy/CICFlowMeter live capture.

### 4.3 Implemented Machine Learning Pipeline

Discuss:

- CIC-IDS-2017 main profile.
- NSL-KDD batch benchmark profile.
- BENIGN-only train/calibration/test split.
- RobustScaler + PCA whitening.
- fitted `r` and `r_s` values derived from benign PCA geometry.
- V-Detector NSA.
- Raw and PCA Self-Boundary.
- Isolation Forest baseline.
- Benign-only conformal threshold calibration.

### 4.4 System Output

Discuss:

- Dashboard stat cards.
- Live traffic chart.
- Severity distribution.
- Alert table.
- Raw flow capture.
- Export full features.
- Alert summary CSV.
- Training logs.
- Detection logs.
- Fitted Self-Gap Radius and Fitted Detector Tolerance shown after training.

### 4.5 System Testing and Evaluation

Discuss:

- Backend/API tests if included.
- ML validation checks.
- Training result metrics.
- Benign FPR.
- Self-intrusion rate.
- Labelled verification results.
- Limitation of accuracy under class imbalance.

### 4.6 Security Testing

Discuss:

- JWT route protection.
- WebSocket token rejection.
- bcrypt password storage.
- admin-only user management.
- deployment limitations.

## 18. Chapter 5 Replacement Structure

### 5.1 Project Requirements Achieved

The system achieved:

- AIS/NSA anomaly detection prototype.
- Isolation Forest baseline.
- React dashboard.
- FastAPI backend.
- Batch detection.
- Live capture for CIC-IDS-2017 flow features.
- JWT authentication.
- SQLite alert persistence.
- Exportable alert summaries.
- Runtime settings.
- User and role management.

### 5.2 Project Constraints

State clearly:

- Academic prototype, not production SOC.
- Live capture requires local privileges and Npcap/Scapy.
- Cloud deployment cannot directly see local network traffic.
- SQLite is acceptable for demo/FYP but not ideal for multi-user production.
- Attack attribution is heuristic and should not be treated as guaranteed ground truth.
- Model performance depends on representative BENIGN training data.
- MFA is not implemented.
- Default secrets/passwords must be changed before exposure.
- NSA `r` and `r_s` are fitted from data in the normal pipeline, not reliable manual tuning sliders.

### 5.3 Future Enhancements

Keep only future work that is still future:

- MFA/2FA.
- Password-change flow.
- Production secret management.
- Restricted CORS and HTTPS deployment.
- Multi-sensor architecture.
- SIEM integration.
- Better live-capture buffering and flow flushing.
- More external validation on unseen networks.
- Stronger model monitoring and drift detection.
- Role-based permissions beyond admin/analyst basics.
- PostgreSQL or managed database for production deployment.
- Optional Advanced/Research mode for manual ablation of `r`, `r_s`, and other NSA internals.

### 5.4 Conclusion

Recommended wording:

> AIS-Detect successfully evolved from a conceptual FYP design into a working academic prototype for AIS-based network anomaly detection. The implemented system combines a FastAPI backend, React frontend, SQLite persistence, JWT authentication, live WebSocket updates, CIC-IDS-2017-compatible live capture, batch detection, and a strict benign-only AIS training pipeline. The project demonstrates how the Negative Selection Algorithm can be adapted into a practical web-based anomaly detection workflow. However, the system remains an academic prototype and should be presented honestly as a research and demonstration tool rather than a production SOC platform.

## 19. Final Checklist for Updating the PDF

Update these sections first:

1. Abstract
2. 1.4 Scope
3. 1.5 Constraints
4. 1.8 Summary
5. 2.3.2 Proposed System Technologies
6. 2.3.3 Comparative Analysis
7. 3.2 Development Approach
8. 3.4 Logical Design
9. 3.5 Database Design
10. 3.6 Prototype
11. Chapter 4
12. Chapter 5
13. Appendix D Future Work

Remove or correct these outdated claims:

- NSL-KDD is the main live dataset.
- Flask backend.
- FastAPI/WebSocket/live capture are future work.
- Account page supports password update and 2FA.
- The system is production SOC-ready.
- Accuracy is the main success metric.
- 2D detector visualization is the actual detection space.
- Training automatically handles unlabeled dirty traffic.
- NSA `r` and `r_s` are normal user-tuned sliders in the main workflow.

Use these current claims instead:

- CIC-IDS-2017 is the live-compatible main profile.
- NSL-KDD is batch-only benchmark.
- FastAPI backend and React/Vite frontend are implemented.
- JWT authentication and token-protected WebSocket are implemented.
- RobustScaler and PCA are fitted only on BENIGN training rows.
- NSA detector generation happens in PCA-whitened space.
- `r` and `r_s` are fitted from benign PCA-space nearest-neighbour geometry.
- Mature V-detectors are primary anomaly evidence.
- PCA Self-Boundary supports final AIS score fusion.
- Raw Self-Boundary supports alert explanation.
- Attack labels are used only for post-run verification.
- The system is an academic prototype requiring further hardening before production use.
