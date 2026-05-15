"""
Security Exploiter & Auditor
============================
Brutally critical automated audit of the AIS-Detect system.
"""

import unittest
import inspect
import os
import sys
from fastapi import HTTPException

# Allow this file to be run directly from "validate and test/" or repo root.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.routers.firewall import _sanitise_ip

class TestAISSecurity(unittest.TestCase):

    def test_auth_token_vulnerability(self):
        """Auth tokens must be signed JWTs, not predictable demo strings."""
        from app.routers.auth import create_access_token
        token = create_access_token({"sub": "admin"})
        self.assertNotIn("demo-token-", token)
        self.assertEqual(len(token.split(".")), 3, "JWT should contain header.payload.signature")

    def test_firewall_injection_vectors(self):
        """CRITICAL: Check if IP sanitisation prevents PowerShell injection."""
        danger_ips = [
            "1.2.3.4; Whoami",
            "1.2.3.4 | calc",
            "1.2.3.4' -Action Allow #",
            "$(calc)",
            "192.168.1.1 & del C:\\"
        ]
        for dip in danger_ips:
            with self.subTest(ip=dip):
                with self.assertRaises(HTTPException) as cm:
                    _sanitise_ip(dip)
                self.assertEqual(cm.exception.status_code, 400)

    def test_model_evasion_logic(self):
        """NSA should auto-calibrate thresholds by default."""
        from app.models.nsa import NegativeSelectionDetector
        nsa = NegativeSelectionDetector(r=0.5)
        self.assertTrue(nsa.auto_threshold)

    def test_websocket_auth_missing(self):
        """CRITICAL: Check if WebSocket endpoint has authentication."""
        from app.routers.capture import websocket_live
        sig = inspect.signature(websocket_live)
        params = [str(p) for p in sig.parameters.values()]
        # Check for presence of token-based WebSocket authentication.
        has_auth = any("token" in p.lower() or "Depends" in p for p in params)
        self.assertTrue(has_auth, "WebSocket endpoint should require token authentication.")

if __name__ == "__main__":
    unittest.main()
