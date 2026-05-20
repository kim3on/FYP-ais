"""
User Management Router
=======================
GET    /api/users            — List all users (Admin only)
POST   /api/users            — Create a new user (Admin only)
DELETE /api/users/{username} — Delete an existing user (Admin only)
"""

import logging
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.db_models import UserDB
from app.schemas import UserCreateRequest
from app.routers.auth import (
    require_admin_user,
    serialize_user,
    get_password_hash,
    ensure_user_profile,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/users",
    tags=["users"],
    dependencies=[Depends(require_admin_user)]
)

@router.get("")
async def list_users(db: Session = Depends(get_db)):
    """List all registered users and their profiles."""
    try:
        users = db.query(UserDB).all()
        return [serialize_user(db, u) for u in users]
    except Exception as e:
        logger.error(f"Failed to list users: {e}")
        raise HTTPException(status_code=500, detail="Internal server error while fetching users")

@router.post("")
async def create_user(req: UserCreateRequest, db: Session = Depends(get_db)):
    """Create a new user and initialize their profile."""
    username = req.username.strip()
    role = req.role.strip()
    
    if not username or not req.password or not role:
        raise HTTPException(status_code=400, detail="Username, password, and role are required")
        
    # Check if user already exists
    existing = db.query(UserDB).filter(UserDB.username == username).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"User '{username}' already exists")
        
    try:
        hashed_password = get_password_hash(req.password)
        new_user = UserDB(username=username, password=hashed_password, role=role)
        db.add(new_user)
        db.flush()
        
        # Initialize their default profile
        ensure_user_profile(db, new_user)
        
        db.commit()
        db.refresh(new_user)
        return serialize_user(db, new_user)
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create user: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create user: {str(e)}")

@router.delete("/{username}")
async def delete_user(
    username: str, 
    current_user: UserDB = Depends(require_admin_user), 
    db: Session = Depends(get_db)
):
    """Delete a user. Prevent administrators from deleting themselves."""
    target_username = username.strip()
    
    if current_user.username == target_username:
        raise HTTPException(status_code=400, detail="You cannot delete your own admin account")
        
    user = db.query(UserDB).filter(UserDB.username == target_username).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{target_username}' not found")
        
    try:
        db.delete(user)
        db.commit()
        return {"success": True, "message": f"User '{target_username}' successfully deleted"}
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to delete user: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete user: {str(e)}")
