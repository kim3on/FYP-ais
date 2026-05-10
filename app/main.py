"""
AIS-Detect FastAPI Backend
===========================
Thin application factory.  All route logic lives in app/routers/.

Run with:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

Routers
-------
auth        — POST /api/auth/login
training    — POST /api/train, GET /api/train/logs, GET /api/train/result
detection   — POST /api/detect/*, GET /api/detect/*
alerts      — GET/PATCH /api/alerts/*
capture     — POST/GET /api/capture/*, WS /ws/live
dashboard   — GET /api/system/status, /api/dashboard/stats,
              /api/model/summary, PATCH /api/settings, GET /health

Frontend
--------
Development : Run `npm run dev` in frontend/ — Vite serves on port 5173
              with a proxy to this backend on port 8000.

Production  : Run `npm run build` in frontend/ — output lands in
              app/static_react/. FastAPI serves it as static files at GET /
              so the entire app is served from a single uvicorn process.
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.routers import auth, training, detection, alerts, capture, dashboard, firewall
from app.routers.auth import get_password_hash
from app.core.database import engine
from app.models.db_models import Base, BlockedIPDB, UserDB
from app.core.database import SessionLocal
from app.routers.firewall import _blocked_ips

# ── App factory ──────────────────────────────────────────────────────────
app = FastAPI(
    title="AIS-Detect API",
    description="Web-Based Network Anomaly Detection using Artificial Immune Systems",
    version="4.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register API routers ──────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(training.router)
app.include_router(detection.router)
app.include_router(alerts.router)
app.include_router(capture.router)
app.include_router(dashboard.router)
app.include_router(firewall.router)

@app.on_event("startup")
def on_startup():
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    # Seed users if database is empty
    if db.query(UserDB).count() == 0:
        db.add_all([
            UserDB(username="admin", password=get_password_hash("password"), role="Network Administrator"),
            UserDB(username="analyst", password=get_password_hash("analyst123"), role="Security Analyst")
        ])
        db.commit()

    # Load blocked IPs into memory
    blocked = db.query(BlockedIPDB).all()
    for b in blocked:
        _blocked_ips[b.ip] = {
            "ip": b.ip,
            "blocked_at": b.blocked_at,
            "reason": b.reason,
            "rule_name": b.rule_name
        }
    db.close()

# ── Serve React frontend (production build) ───────────────────────────────
# After running `npm run build` in frontend/, the output lands in
# app/static_react/.  We mount the assets directory and add a catch-all
# route that returns index.html for every non-API path (SPA routing).
_REACT_BUILD = Path(__file__).parent / "static_react"

if _REACT_BUILD.exists():
    # Serve JS/CSS/image assets from /assets/*
    _assets = _REACT_BUILD / "assets"
    if _assets.exists():
        app.mount("/assets", StaticFiles(directory=str(_assets)), name="react-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_react(full_path: str):
        """
        SPA catch-all — returns index.html for every route that is not
        an /api/* or /ws/* endpoint so React Router handles the URL.
        """
        # Let API and docs routes pass through to their routers
        if full_path.startswith(("api/", "ws/", "docs", "redoc", "openapi")):
            from fastapi import HTTPException
            raise HTTPException(status_code=404)
        index = _REACT_BUILD / "index.html"
        return FileResponse(str(index))
