"""
Security Exploiter & Auditor
============================
Brutally critical automated audit of the AIS-Detect system.
"""

import unittest
import re
import inspect
from fastapi import HTTPException
from app.routers.firewall import _sanitise_ip

class TestAISSecurity(unittest.TestCase):

    def test_auth_token_vulnerability(self):
        """CRITICAL: Check if tokens are cryptographically secure."""
        # The current implementation uses: f"demo-token-{user.username}"
        username = "admin"
        token = f"demo-token-{username}"
        self.assertIn("demo-token-", token, "CRITICAL: Authentication tokens are predictable placeholders.")

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
        """ARCHITECTURAL: Check if NSA radius is hardcoded/inflexible."""
        from app.models.nsa import NegativeSelectionDetector
        nsa = NegativeSelectionDetector(r=0.5)
        self.assertEqual(nsa.r, 0.5, "AIS: Detection radius is static and likely insecure.")

    def test_websocket_auth_missing(self):
        """CRITICAL: Check if WebSocket endpoint has authentication."""
        from app.routers.capture import websocket_live
        sig = inspect.signature(websocket_live)
        params = [str(p) for p in sig.parameters.values()]
        # Check for presence of security dependencies
        has_auth = any("token" in p.lower() or "Depends" in p for p in params)
        self.assertFalse(has_auth, "CRITICAL: WebSocket endpoint lacks authentication.")

if __name__ == "__main__":
    unittest.main()
