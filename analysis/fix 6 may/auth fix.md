# Authentication Implementation Plan

## Objective
Replace the mock authentication system with a robust, production-ready JWT-based authentication system. Passwords will be securely hashed using bcrypt, and all non-health API endpoints will be protected by requiring a valid JWT with an assigned role.

## Key Files & Context
- `requirements.txt`: Needs authentication libraries.
- `app/routers/auth.py`: Needs JWT logic, password hashing utilities, and a FastAPI dependency for route protection.
- `app/main.py`: Needs to securely hash passwords when seeding the initial database.
- `app/routers/alerts.py`, `capture.py`, `dashboard.py`, `detection.py`, `firewall.py`, `training.py`: Need to enforce authentication on all non-health endpoints.

## Implementation Steps

### 1. Update Dependencies
Add the following packages to `requirements.txt`:
- `PyJWT>=2.8.0`
- `passlib[bcrypt]>=1.7.4`

### 2. Implement Core Auth Logic (`app/routers/auth.py`)
- Add `passlib.context.CryptContext` to handle bcrypt password hashing and verification.
- Add JWT creation logic using `jwt.encode` with a defined `SECRET_KEY` and expiration time (e.g., 24 hours).
- Implement `get_current_user` dependency using FastAPI's `OAuth2PasswordBearer`:
  - Decode the token and extract the username.
  - Fetch the user from the database.
  - Verify that the user exists and has a valid role assigned (Role check: any valid role is allowed).
  - Raise `HTTPException(401)` if the token is invalid, expired, or the user lacks a role.
- Update the `/login` endpoint to:
  - Verify the hashed password against the stored hash.
  - Return a signed JWT token instead of a mock string.

### 3. Secure Initial User Seeding (`app/main.py`)
- Import the password hashing utility from `app.routers.auth`.
- Update the database seeding logic in the `on_startup` event:
  - Hash the passwords for the `admin` and `analyst` users before inserting them into the database.

### 4. Protect API Endpoints
Apply the `get_current_user` dependency to all protected routes. 
- For routers that contain *only* protected endpoints (`alerts.py`, `detection.py`, `firewall.py`, `training.py`), apply the dependency at the router level:
  `router = APIRouter(..., dependencies=[Depends(get_current_user)])`
- For `dashboard.py`: Apply `Depends(get_current_user)` to the function signatures of `/api/system/status`, `/api/dashboard/stats`, `/api/model/summary`, and `/api/settings`. The `/health` and `/` endpoints will remain public.
- For `capture.py`: 
  - Apply the dependency to all `/api/capture/*` REST endpoints.
  - For the WebSocket endpoint `/ws/live`, extract the token from query parameters (`token=...`), decode it using the auth utility, and close the connection with `status.WS_1008_POLICY_VIOLATION` if invalid.

## Verification & Testing
- Attempt to access a protected endpoint (e.g., `/api/dashboard/stats`) without a token and ensure a 401 Unauthorized response is returned.
- Call the `/api/auth/login` endpoint with valid credentials to receive a JWT.
- Ensure the JWT can be used in the `Authorization: Bearer <token>` header to successfully access protected endpoints.
- Ensure the `/health` endpoint remains accessible without authentication.
- Test the WebSocket connection with a valid token query parameter to ensure live capture data is streamed correctly.



Key Changes
   1. Secure Hashing & JWT: Integrated PyJWT and passlib[bcrypt]. All passwords are now stored as secure hashes, and the mock demo token has been replaced with signed 
      JWTs valid for 24 hours.
   2. Auth Dependency: Implemented a get_current_user dependency in app/routers/auth.py that validates the JWT, checks for a valid user in the database, and ensures   
      they have an assigned role.
   3. Global Protection: Applied the auth dependency at the router level for critical services:
       * Training: /api/train/*
       * Detection: /api/detect/*
       * Firewall: /api/firewall/*
       * Alerts: /api/alerts/*
   4. Granular Security:
       * Protected specific dashboard stats and settings endpoints while keeping /health public.
       * Secured all capture REST endpoints.
       * WebSocket Security: Added manual JWT verification to the live capture stream (/ws/live), requiring a valid token via query parameter.
   5. Secure Seeding: Updated app/main.py to securely hash the default admin and analyst accounts during the initial database setup.

  The backend now enforces strict access control across all non-health endpoints, ensuring no critical actions can be performed unauthenticated.