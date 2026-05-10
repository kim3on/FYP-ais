"""
Auth Router
============
POST /api/auth/login  — authenticate a user and return a session token.
"""

import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.schemas import LoginRequest
from app.core.database import get_db
from app.models.db_models import UserDB

# ── Auth Configuration ───────────────────────────────────────────────────
SECRET_KEY = "ais-detect-secret-key-change-me-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

router = APIRouter(prefix="/api/auth", tags=["auth"])

# ── Utilities ─────────────────────────────────────────────────────────────

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain text password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except (ValueError, TypeError):
        return False

def get_password_hash(password: str) -> str:
    """Generate a bcrypt hash from a plain text password."""
    # Salt and hash the password, then decode to string for DB storage
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Dependency that verifies the JWT and returns the authenticated UserDB object.
    Requires that the user exists and has a valid role.
    """
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if user is None:
        raise credentials_exception
    
    if not user.role:
        raise HTTPException(status_code=403, detail="User has no role assigned")
        
    return user

# ── Endpoints ─────────────────────────────────────────────────────────────

@router.post("/login")
async def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == req.username).first()
    if not user or not verify_password(req.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    access_token = create_access_token(data={"sub": user.username})
    
    return {
        "success":  True,
        "username": user.username,
        "role":     user.role,
        "token":    access_token,
    }
