"""
AIS-Detect User Management Utility
==================================
Usage:
    python manage_users.py add <username> <password> <role>
    python manage_users.py list
    python manage_users.py delete <username>
"""

import sys
from sqlalchemy.orm import Session
from app.core.database import SessionLocal, engine
from app.models.db_models import UserDB, Base
from app.routers.auth import get_password_hash, ensure_user_profile

def add_user(username, password, role):
    db = SessionLocal()
    try:
        # Check if exists
        existing = db.query(UserDB).filter(UserDB.username == username).first()
        if existing:
            print(f"Error: User '{username}' already exists.")
            return

        hashed_password = get_password_hash(password)
        new_user = UserDB(username=username, password=hashed_password, role=role)
        db.add(new_user)
        db.flush()
        ensure_user_profile(db, new_user)
        db.commit()
        print(f"Successfully added user '{username}' with role '{role}'.")
    finally:
        db.close()

def list_users():
    db = SessionLocal()
    try:
        users = db.query(UserDB).all()
        print(f"{'ID':<5} | {'Username':<15} | {'Role':<25} | {'Display Name':<20} | {'SOC Tier':<14} | {'Shift':<12}")
        print("-" * 104)
        for u in users:
            profile = ensure_user_profile(db, u)
            print(
                f"{u.id:<5} | {u.username:<15} | {u.role:<25} | "
                f"{(profile.display_name or ''):<20} | {(profile.soc_tier or ''):<14} | {(profile.shift or ''):<12}"
            )
        db.commit()
    finally:
        db.close()

def delete_user(username):
    db = SessionLocal()
    try:
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if not user:
            print(f"Error: User '{username}' not found.")
            return
        
        db.delete(user)
        db.commit()
        print(f"Successfully deleted user '{username}'.")
    finally:
        db.close()

if __name__ == "__main__":
    # Ensure tables exist
    Base.metadata.create_all(bind=engine)

    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "add" and len(sys.argv) == 5:
        add_user(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "list":
        list_users()
    elif cmd == "delete" and len(sys.argv) == 3:
        delete_user(sys.argv[2])
    else:
        print("Invalid command or arguments.")
        print(__doc__)
