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
              /api/model/summary, PATCH /api/settings, GET /health, GET /
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import auth, training, detection, alerts, capture, dashboard

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

# ── Register routers ─────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(training.router)
app.include_router(detection.router)
app.include_router(alerts.router)
app.include_router(capture.router)
app.include_router(dashboard.router)
