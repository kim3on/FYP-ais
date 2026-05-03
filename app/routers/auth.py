"""
Auth Router
============
POST /api/auth/login  — authenticate a user and return a session token.
"""

from fastapi import APIRouter, HTTPException
from app.schemas import LoginRequest
from app.state import _USERS

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login")
async def login(req: LoginRequest):
    user = _USERS.get(req.username)
    if not user or user["password"] != req.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {
        "success":  True,
        "username": req.username,
        "role":     user["role"],
        "token":    f"demo-token-{req.username}",   # use JWT in production
    }
