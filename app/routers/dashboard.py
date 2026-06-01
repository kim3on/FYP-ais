"""
Dashboard Router
=================
GET   /api/system/status     — system health & model state
GET   /api/dashboard/stats   — aggregate counts for the four stat cards
GET   /api/model/summary     — metadata for both trained models
PATCH /api/settings          — switch active model / alert threshold
GET   /health                — simple health check
GET   /api                   — HTML landing page with API overview
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import func

from app.core.pipeline import (
    engine_ready,
    load_nsa,
    load_iso,
    load_self_boundary,
    load_pca_self_boundary,
    models_ready,
)
from app.core.datasets import DATASET_CICIDS2017, dataset_display_name
from app.schemas import SettingsUpdate
from app.state import (
    DEFAULT_ALERT_THRESHOLD,
    DEFAULT_ZERO_DAY_THRESHOLD,
    RUNTIME_ALERT_THRESHOLD_ENABLED,
    _state,
    save_runtime_settings,
)
from app.routers.auth import get_current_user, require_admin_user

router = APIRouter(tags=["dashboard"])


# ═══════════════════════════════════════════════════════════════════════
#  SYSTEM STATUS
# ═══════════════════════════════════════════════════════════════════════

@router.get("/api/system/status")
async def system_status(user=Depends(get_current_user)):
    """System health and model readiness."""
    dataset_type = _state.get("active_dataset_type", DATASET_CICIDS2017)
    full_ready = models_ready(dataset_type)
    active_ready = engine_ready(_state["active_model"], dataset_type)
    nsa   = load_nsa(dataset_type)
    iso   = load_iso(dataset_type)
    active_stat = _active_engine_stat(_state["active_model"], nsa, iso)
    return {
        "status":         _state["status"] if active_ready else "idle",
        "models_ready":   full_ready,
        "active_engine_ready": active_ready,
        "active_model":   _state["active_model"],
        "active_detection_engine": _state["active_model"],
        "active_dataset_type": dataset_type,
        "dataset_display": dataset_display_name(dataset_type),
        "packet_count":   _state["packet_count"],
        "anomaly_count":  _state["anomaly_count"],
        "threshold":      float(
            _state.get("threshold", DEFAULT_ALERT_THRESHOLD)
            if RUNTIME_ALERT_THRESHOLD_ENABLED
            else DEFAULT_ALERT_THRESHOLD
        ),
        "runtime_alert_threshold_enabled": RUNTIME_ALERT_THRESHOLD_ENABLED,
        "zero_day_threshold": float(_state.get("zero_day_threshold", DEFAULT_ZERO_DAY_THRESHOLD)),
        "antibody_count": nsa.meta_.get("mature_detectors", 0) if (nsa and nsa.is_fitted_) else 0,
        "isolation_tree_count": iso.n_estimators if (iso and iso.is_fitted_) else 0,
        "active_model_stat_label": active_stat["label"],
        "active_model_stat_value": active_stat["value"],
        "active_model_stat_subtitle": active_stat["subtitle"],
        "server_time":    datetime.utcnow().isoformat(),
    }


# ═══════════════════════════════════════════════════════════════════════
#  DASHBOARD STATS
# ═══════════════════════════════════════════════════════════════════════

@router.get("/api/dashboard/stats")
async def dashboard_stats(user=Depends(get_current_user)):
    """Aggregate counts for the stat cards — reads from persistent DB."""
    from app.core.database import SessionLocal
    from app.models.db_models import AlertDB

    db = SessionLocal()
    try:
        total_anomalies = db.query(func.count(AlertDB.id)).scalar() or 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        rows = (
            db.query(func.lower(AlertDB.severity), func.count(AlertDB.id))
            .group_by(func.lower(AlertDB.severity))
            .all()
        )
        for severity, count in rows:
            sev = (severity or "low").lower()
            if sev in severity_counts:
                severity_counts[sev] += int(count or 0)
    finally:
        db.close()

    dataset_type = _state.get("active_dataset_type", DATASET_CICIDS2017)
    nsa        = load_nsa(dataset_type)
    iso        = load_iso(dataset_type)
    antibodies = nsa.meta_.get("mature_detectors", 0) if (nsa and nsa.is_fitted_) else 0
    iso_trees = iso.n_estimators if (iso and iso.is_fitted_) else 0
    active_stat = _active_engine_stat(_state["active_model"], nsa, iso)

    return {
        "total_packets":     _state["packet_count"],
        "anomalies_total":   total_anomalies,
        "critical_alerts":   severity_counts["critical"],
        "active_antibodies": antibodies,
        "isolation_trees":   iso_trees,
        "active_engine":     _state["active_model"],
        "active_detection_engine": _state["active_model"],
        "active_engine_ready": engine_ready(_state["active_model"], dataset_type),
        "active_model_stat_label": active_stat["label"],
        "active_model_stat_value": active_stat["value"],
        "active_model_stat_subtitle": active_stat["subtitle"],
        "severity_counts":   severity_counts,
        "system_status":     _state["status"],
    }


# ═══════════════════════════════════════════════════════════════════════
#  MODEL INFO & SETTINGS
# ═══════════════════════════════════════════════════════════════════════

@router.get("/api/model/summary")
async def model_summary(user=Depends(get_current_user)):
    """Return metadata for both trained models."""
    dataset_type = _state.get("active_dataset_type", DATASET_CICIDS2017)
    nsa = load_nsa(dataset_type)
    iso = load_iso(dataset_type)
    raw_sb = load_self_boundary(dataset_type)
    pca_sb = load_pca_self_boundary(dataset_type)
    nsa_summary = nsa.summary() if nsa else {"status": "not_trained"}
    iso_summary = iso.summary() if iso else {"status": "not_trained"}
    return {
        "nsa":              nsa_summary,
        "isolation_forest": iso_summary,
        "raw_self_boundary_evidence": raw_sb.summary() if raw_sb else {"status": "not_trained"},
        "pca_self_boundary": pca_sb.summary() if pca_sb else {"status": "not_trained"},
        "dataset_type": dataset_type,
        "dataset_display": dataset_display_name(dataset_type),
        "models_ready": models_ready(dataset_type),
        "active_engine_ready": engine_ready(_state["active_model"], dataset_type),
        "ais_detection": {
            "detector_count": nsa_summary.get("mature_detectors", 0),
            "fusion_mode": "NSA + PCA-space Self-Boundary + benign-calibrated fusion threshold",
            "pca_self_boundary_status": "active" if pca_sb else "legacy_missing",
            "raw_self_boundary_evidence_status": "active" if raw_sb else "missing",
        },
        "active":           _state["active_model"],
        "active_detection_engine": _state["active_model"],
    }


@router.patch("/api/settings")
async def update_settings(settings: SettingsUpdate, user=Depends(require_admin_user)):
    """Update runtime settings (active model, alert threshold)."""
    changed = False
    if settings.active_model is not None:
        if settings.active_model not in ("nsa", "isolation_forest"):
            raise HTTPException(status_code=400, detail="Invalid active_model")

        if settings.active_model == "nsa":
            model = load_nsa(_state.get("active_dataset_type", DATASET_CICIDS2017))
            if model is None or not getattr(model, "is_fitted_", False):
                raise HTTPException(status_code=400, detail="NSA model is not trained")
        else:
            model = load_iso(_state.get("active_dataset_type", DATASET_CICIDS2017))
            if model is None or not getattr(model, "is_fitted_", False):
                raise HTTPException(status_code=400, detail="Isolation Forest model is not trained")

        _state["active_model"] = settings.active_model
        changed = True

    if settings.threshold is not None:
        threshold = float(settings.threshold)
        if not 0.10 <= threshold <= 0.90:
            raise HTTPException(status_code=400, detail="threshold must be between 0.10 and 0.90")
        _state["threshold"] = threshold if RUNTIME_ALERT_THRESHOLD_ENABLED else DEFAULT_ALERT_THRESHOLD
        changed = True

    if settings.zero_day_threshold is not None:
        zero_day_threshold = float(settings.zero_day_threshold)
        if not 0.30 <= zero_day_threshold <= 0.95:
            raise HTTPException(status_code=400, detail="zero_day_threshold must be between 0.30 and 0.95")
        _state["zero_day_threshold"] = zero_day_threshold
        changed = True

    if changed:
        save_runtime_settings()

    return {
        "success": True,
        "active_model": _state["active_model"],
        "active_detection_engine": _state["active_model"],
        "active_engine_ready": engine_ready(_state["active_model"], _state.get("active_dataset_type", DATASET_CICIDS2017)),
        "active_dataset_type": _state.get("active_dataset_type", DATASET_CICIDS2017),
        "threshold": float(
            _state.get("threshold", DEFAULT_ALERT_THRESHOLD)
            if RUNTIME_ALERT_THRESHOLD_ENABLED
            else DEFAULT_ALERT_THRESHOLD
        ),
        "runtime_alert_threshold_enabled": RUNTIME_ALERT_THRESHOLD_ENABLED,
        "zero_day_threshold": float(_state.get("zero_day_threshold", DEFAULT_ZERO_DAY_THRESHOLD)),
    }


def _active_engine_stat(active_model: str, nsa, iso) -> dict:
    if active_model == "isolation_forest":
        return {
            "label": "Isolation Trees",
            "value": int(getattr(iso, "n_estimators", 0) or 0) if (iso and getattr(iso, "is_fitted_", False)) else 0,
            "subtitle": "Isolation Forest baseline",
        }
    return {
        "label": "Active Antibodies",
        "value": int(nsa.meta_.get("mature_detectors", 0)) if (nsa and getattr(nsa, "is_fitted_", False)) else 0,
        "subtitle": "Generated via Negative Selection",
    }


# ═══════════════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ═══════════════════════════════════════════════════════════════════════

@router.get("/health")
async def health():
    return {"status": "ok", "version": "4.0.0"}


# ═══════════════════════════════════════════════════════════════════════
#  HTML LANDING PAGE
# ═══════════════════════════════════════════════════════════════════════

@router.get("/api", response_class=HTMLResponse)
async def root():
    """Landing page with API overview and quick links."""
    ready        = models_ready()
    status_color = "#059669" if ready else "#D97706"
    status_text  = "Models ready — system active" if ready else "No models trained yet"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIS-Detect API</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'DM Sans', sans-serif;
    background: #0D1117; color: #E6EDF3;
    min-height: 100vh;
    display: flex; align-items: flex-start; justify-content: center;
    padding: 48px 20px;
  }}
  .container {{ width: 100%; max-width: 780px; }}
  .header {{ margin-bottom: 32px; }}
  .brand {{ display: flex; align-items: center; gap: 14px; margin-bottom: 16px; }}
  .brand-icon {{
    width: 44px; height: 44px; background: #2563EB;
    border-radius: 10px; display: flex; align-items: center; justify-content: center;
  }}
  .brand-icon svg {{ width: 24px; height: 24px; }}
  .brand-name {{ font-size: 22px; font-weight: 700; letter-spacing: -0.4px; }}
  .brand-sub  {{ font-size: 13px; color: #7D8590; margin-top: 2px; }}
  .status-row {{
    display: inline-flex; align-items: center; gap: 8px;
    background: #161B22; border: 1px solid #21262D;
    border-radius: 20px; padding: 6px 14px;
    font-size: 12px; font-weight: 500;
  }}
  .status-dot {{
    width: 7px; height: 7px; border-radius: 50%;
    background: {status_color}; animation: pulse 2s ease infinite;
  }}
  @keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:0.4}} }}
  .status-text {{ color: {status_color}; }}
  .section {{ margin-bottom: 24px; }}
  .section-title {{
    font-size: 11px; font-weight: 600; letter-spacing: 0.06em;
    text-transform: uppercase; color: #7D8590; margin-bottom: 12px;
  }}
  .card {{ background: #161B22; border: 1px solid #21262D; border-radius: 10px; overflow: hidden; }}
  .card-row {{
    display: flex; align-items: center; padding: 11px 16px;
    border-bottom: 1px solid #21262D; gap: 12px;
    text-decoration: none; transition: background 0.12s;
  }}
  .card-row:last-child {{ border-bottom: none; }}
  .card-row:hover {{ background: rgba(255,255,255,0.03); }}
  .method {{
    font-family: 'DM Mono', monospace; font-size: 10px; font-weight: 500;
    padding: 2px 7px; border-radius: 4px; min-width: 42px;
    text-align: center; flex-shrink: 0;
  }}
  .GET   {{ background: rgba(5,150,105,0.12);  color: #059669; }}
  .POST  {{ background: rgba(37,99,235,0.12);  color: #2563EB; }}
  .PATCH {{ background: rgba(217,119,6,0.12);  color: #D97706; }}
  .WS    {{ background: rgba(139,92,246,0.12); color: #7C3AED; }}
  .path {{ font-family: 'DM Mono', monospace; font-size: 12px; color: #E6EDF3; flex: 1; }}
  .desc {{ font-size: 12px; color: #7D8590; }}
  .quick-links {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 20px; }}
  .link-btn {{
    display: inline-flex; align-items: center; gap: 6px;
    background: #161B22; border: 1px solid #21262D;
    border-radius: 6px; padding: 8px 14px;
    font-size: 12px; font-weight: 500; color: #E6EDF3;
    text-decoration: none; transition: all 0.12s;
  }}
  .link-btn:hover {{ background: #1C2330; border-color: #30363D; }}
  .link-btn.primary {{ background: #2563EB; border-color: #2563EB; color: #fff; }}
  .link-btn.primary:hover {{ background: #1D4ED8; }}
  .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
  .info-card {{
    background: #161B22; border: 1px solid #21262D;
    border-radius: 8px; padding: 14px 16px;
  }}
  .info-label {{ font-size: 11px; color: #7D8590; margin-bottom: 4px; }}
  .info-value {{ font-family: 'DM Mono', monospace; font-size: 13px; font-weight: 500; }}
  .info-value.accent  {{ color: #2563EB; }}
  .info-value.success {{ color: #059669; }}
  .info-value.warning {{ color: #D97706; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="brand">
      <div class="brand-icon">
        <svg viewBox="0 0 24 24" fill="none">
          <polygon points="12,2 22,7 22,17 12,22 2,17 2,7" stroke="white" stroke-width="1.5" fill="rgba(255,255,255,0.15)"/>
          <circle cx="12" cy="12" r="3.5" stroke="white" stroke-width="1.5" fill="none"/>
          <circle cx="12" cy="12" r="1.2" fill="white"/>
        </svg>
      </div>
      <div>
        <div class="brand-name">AIS-Detect API</div>
        <div class="brand-sub">Network Anomaly Detection — Artificial Immune Systems · v4.0.0</div>
      </div>
    </div>
    <div class="status-row">
      <div class="status-dot"></div>
      <span class="status-text">{status_text}</span>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Quick Access</div>
    <div class="quick-links">
      <a href="/docs"              class="link-btn primary">Interactive API Docs (Swagger)</a>
      <a href="/redoc"             class="link-btn">ReDoc</a>
      <a href="/api/system/status" class="link-btn">System Status</a>
      <a href="/api/model/summary" class="link-btn">Model Summary</a>
    </div>
  </div>

  <div class="section">
    <div class="section-title">System Info</div>
    <div class="info-grid">
      <div class="info-card">
        <div class="info-label">Models</div>
        <div class="info-value {'success' if ready else 'warning'}">{'● Trained &amp; Ready' if ready else '○ Not Trained'}</div>
      </div>
      <div class="info-card">
        <div class="info-label">Algorithm</div>
        <div class="info-value accent">Negative Selection (NSA)</div>
      </div>
      <div class="info-card">
        <div class="info-label">Dataset</div>
        <div class="info-value">CIC-IDS-2017</div>
      </div>
      <div class="info-card">
        <div class="info-label">Server Time</div>
        <div class="info-value">{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Endpoints</div>
    <div class="card">
      <div class="card-row"><span class="method POST">POST</span><span class="path">/api/auth/login</span><span class="desc">Authenticate user</span></div>
      <div class="card-row"><span class="method GET">GET</span><span class="path">/api/system/status</span><span class="desc">System health &amp; model state</span></div>
      <div class="card-row"><span class="method POST">POST</span><span class="path">/api/train</span><span class="desc">Upload dataset &amp; train models</span></div>
      <div class="card-row"><span class="method GET">GET</span><span class="path">/api/train/logs</span><span class="desc">Stream training log lines</span></div>
      <div class="card-row"><span class="method GET">GET</span><span class="path">/api/train/result</span><span class="desc">Last training evaluation results</span></div>
      <div class="card-row"><span class="method POST">POST</span><span class="path">/api/detect</span><span class="desc">Detect anomalies in uploaded log CSV</span></div>
      <div class="card-row"><span class="method POST">POST</span><span class="path">/api/detect/sample</span><span class="desc">Detect anomaly in single JSON flow</span></div>
      <div class="card-row"><span class="method GET">GET</span><span class="path">/api/alerts</span><span class="desc">List all alerts (filter: ?severity=critical)</span></div>
      <div class="card-row"><span class="method PATCH">PATCH</span><span class="path">/api/alerts/{{id}}/fp</span><span class="desc">Mark alert as false positive</span></div>
      <div class="card-row"><span class="method GET">GET</span><span class="path">/api/dashboard/stats</span><span class="desc">Stat card numbers for the dashboard</span></div>
      <div class="card-row"><span class="method GET">GET</span><span class="path">/api/model/summary</span><span class="desc">NSA + Isolation Forest metadata</span></div>
      <div class="card-row"><span class="method PATCH">PATCH</span><span class="path">/api/settings</span><span class="desc">Switch active model / alert threshold</span></div>
      <div class="card-row"><span class="method WS">WS</span><span class="path">/ws/live</span><span class="desc">Real-time live capture stream</span></div>
      <div class="card-row"><span class="method GET">GET</span><span class="path">/health</span><span class="desc">Simple health check</span></div>
    </div>
  </div>
</div>
</body>
</html>"""
