"""
Pydantic Schemas
=================
Request and response body models for the AIS-Detect API.
"""

from pydantic import BaseModel
from typing import Optional


class LoginRequest(BaseModel):
    username: str
    password: str


class TrainConfig(BaseModel):
    r: float = 0.3
    r_s: Optional[float] = None   # Self-tolerance (V-Detector); defaults to min(r*0.1, 0.05)
    max_detectors: int = 500
    max_attempts: int = 10_000
    contamination: float = 0.05
    test_size: float = 0.2


class SettingsUpdate(BaseModel):
    active_model: Optional[str] = None
    alert_threshold: Optional[str] = None
