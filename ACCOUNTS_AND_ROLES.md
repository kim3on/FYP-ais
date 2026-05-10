# User Management & RBAC — AIS-Detect

This document explains how to manage user accounts and roles within the AIS-Detect system.

## 1. Management Utility Script (Recommended)

A standalone utility script `manage_users.py` is provided in the project root for administrative tasks.

### Adding a User
```powershell
python manage_users.py add "<username>" "<password>" "<role>"
```
*Example:* `python manage_users.py add "john_doe" "P@ssword123" "Security Analyst"`

### Listing Users
```powershell
python manage_users.py list
```

### Deleting a User
```powershell
python manage_users.py delete "<username>"
```

---

## 2. Default Seed Users

The system automatically creates default accounts if the `users` table is empty during startup. This logic is located in `app/main.py` within the `on_startup` function.

**Default Credentials:**
- **Admin:** `admin` / `password` (Role: `Network Administrator`)
- **Analyst:** `analyst` / `analyst123` (Role: `Security Analyst`)

---

## 3. Roles and Permissions (RBAC)

Roles in AIS-Detect are descriptive strings stored in the database. They are used for both UI display and API authorization.

### Role-Based Access Control (API)
To restrict an endpoint to specific roles, use a helper function within the router and the `get_current_user` dependency.

**Implementation Example:**
```python
from app.routers.auth import get_current_user

def _require_admin(user):
    role = (getattr(user, "role", "") or "").lower()
    if "administrator" not in role:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

@router.post("/protected-action")
async def protected_action(user=Depends(get_current_user)):
    _require_admin(user)
    # ... logic only accessible by Administrators ...
```

### Role Display (Frontend)
The React frontend retrieves the user's role from the JWT session token. The role is displayed on the **Sidebar** and the **Account** page. 

Assigning a new role string via the management script will reflect immediately in the UI upon the next login.

---

## 4. Technical Details

- **Database:** `app/artefacts/ais_detect.db` (SQLite)
- **Table:** `users` (Columns: `id`, `username`, `password`, `role`)
- **Password Security:** All passwords are hashed using **bcrypt** with a unique salt before being stored.
- **Session Management:** Auth is handled via **JWT (JSON Web Tokens)** with a default 24-hour expiration.
