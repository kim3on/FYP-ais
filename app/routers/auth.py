"""
Auth Router
============
POST /api/auth/login  — authenticate a user and return a session token.
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.schemas import LoginRequest
from app.core.database import get_db
from app.models.db_models import UserDB

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login")
async def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == req.username).first()
    if not user or user.password != req.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    return {
        "success":  True,
        "username": user.username,
        "role":     user.role,
        "token":    f"demo-token-{user.username}",   # use JWT in production
    }
