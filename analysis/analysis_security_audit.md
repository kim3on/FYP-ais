# System-Wide Security Audit Report (Brutally Critical)

**Date:** 2026-05-02
**Skill Context:** @security-auditor @007

> **Current status (May 2026):** This is a historical audit baseline. The May 6 update addressed the original demo-auth findings by adding JWT authentication, bcrypt password hashing, protected non-health API routes, and token validation for `/ws/live`. Keep the findings below as the original risk record, not as the current implementation state.

## 1. Executive Summary
While the AIS-Detect system demonstrates significant technical merit in its immunological approach to anomaly detection, it currently possesses **critical security vulnerabilities** that would allow an attacker to bypass authentication, hijack live network data, and potentially execute code via the active response engine.

## 2. Authentication & API Security

### 2.1 Predictable Authentication Tokens (CRITICAL)
*   **Vulnerability:** The system uses a hardcoded placeholder for tokens: `f"demo-token-{user.username}"`.
*   **Exploit:** An attacker only needs to know a valid username (e.g., `admin`) to reconstruct a valid session token and bypass all authentication.
*   **Recommendation:** Implement standard **JWT (JSON Web Tokens)** with a cryptographically secure `SECRET_KEY`.

### 2.2 Unauthenticated WebSockets (CRITICAL)
*   **Vulnerability:** The `/ws/live` endpoint has **zero authentication checks**.
*   **Exploit:** Any user (authenticated or not) can connect to the WebSocket and receive a real-time stream of network metadata, IP addresses, and anomaly reports.
*   **Recommendation:** Implement token-based authentication during the WebSocket handshake.

### 2.3 Cleartext Password Storage (CRITICAL)
*   **Vulnerability:** The `auth.py` router compares passwords using direct equality: `user.password != req.password`.
*   **Exploit:** If the database is compromised, all user credentials are leaked in plain text.
*   **Recommendation:** Use `argon2-cffi` or `bcrypt` for one-way password hashing.

## 3. Active Response & Command Safety

### 3.1 PowerShell Command Injection (HIGH)
*   **Audit:** The `firewall.py` router constructs shell commands using f-strings: `f'New-NetFirewallRule ... -RemoteAddress {ip}'`.
*   **Observation:** While the current `_sanitise_ip` regex (`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`) is effective against basic string interpolation attacks, using shell-mediated execution for privileged operations remains a high-risk practice.
*   **Recommendation:** Utilize Python's `subprocess` with list-based arguments directly, or use a dedicated Windows API wrapper to avoid shell parsing entirely.

## 4. Anomaly Detection Logic

### 4.1 Adversarial Evasion (ARCHITECTURAL) [PATCHED]
*   **Vulnerability:** The AIS detector originally used a **static radius** ($r=0.5$).
*   **Issue:** In a high-dimensional feature space, a fixed spherical boundary is trivial to evade.
*   **Patch Status:** **RESOLVED**. The system now implements a True V-Detector algorithm with variable activation radii (`r = dist_to_nearest_self - r_s`). This adaptive sizing eliminates the static boundary that adversaries could exploit.

## 5. Summary of Automated Audit (`validate_security.py`)

| Test Case | Status | Severity |
| :--- | :--- | :--- |
| Auth Token Predictability | **RESOLVED MAY 6** | JWT now used |
| WebSocket Authentication | **RESOLVED MAY 6** | token query parameter required |
| IP Sanitisation | **PASS** | LOW (via Regex) |
| Detection Evasion Risk | **MITIGATED** | V-Detector + dynamic PCA-space thresholds |

## 6. Conclusion
The original May 2 implementation was a **"Security Theatre"** implementation. The May 6 security update remediated the most critical authentication and WebSocket exposure issues. Remaining hardening before public deployment includes moving secrets to environment variables, enforcing finer-grained role authorization, restricting CORS, and replacing SQLite for multi-user/cloud deployments.
