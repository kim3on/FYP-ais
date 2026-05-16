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


class UserProfileUpdate(BaseModel):
    display_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    job_title: Optional[str] = None
    soc_tier: Optional[str] = None
    team: Optional[str] = None
    shift: Optional[str] = None
    timezone: Optional[str] = None
    escalation_contact: Optional[str] = None


class TrainConfig(BaseModel):
    r: float = 0.15
    r_s: Optional[float] = None   # Self-tolerance (V-Detector); defaults to min(r*0.1, 0.05)
    max_detectors: int = 3000
    max_attempts: int = 100_000
    contamination: float = 0.05
    test_size: float = 0.2
    n_pca_components: Optional[int] = 25
    benign_row_limit: Optional[int] = 20_000


class SettingsUpdate(BaseModel):
    active_model: Optional[str] = None
    alert_threshold: Optional[str] = None
