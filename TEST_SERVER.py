"""
Automated Test Suite for T&C Red Flag Scanner
Tests Flask API endpoints, static serving, input validation, and scoring consistency.
"""

import unittest
import json
import os
from app import app, analyzer

class TestTCRedFlagScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()

    def test_health_check(self):
        """Verify /api/health returns healthy and correct taxonomy size."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data.get("status"), "healthy")
        self.assertEqual(data.get("team"), "CorruptX")
        self.assertEqual(data.get("offline_capable"), True)
        self.assertEqual(data.get("active_categories"), 14)

    def test_rules_endpoint(self):
        """Verify /api/rules returns all 14 categories."""
        response = self.client.get("/api/rules")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("categories", data)
        self.assertEqual(len(data["categories"]), 14)

    def test_demo_endpoint(self):
        """Verify /api/demo returns preloaded policies."""
        response = self.client.get("/api/demo")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertGreaterEqual(len(data.get("samples", [])), 3)

    def test_scan_empty_input(self):
        """Verify /api/scan rejects empty input with friendly error."""
        response = self.client.post("/api/scan", json={"text": "", "document_name": "Empty"})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("error", data)

    def test_scan_too_short_input(self):
        """Verify /api/scan rejects input that is too short."""
        response = self.client.post("/api/scan", json={"text": "Hello world", "document_name": "Short"})
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("error", data)

    def test_scan_high_risk_policy(self):
        """Verify scan on high-risk clauses detects categories and assigns HIGH RISK."""
        high_risk_text = (
            "We reserve the right to share your personal information with third parties. "
            "We collect information about your activity across third-party websites to build demographic profiles. "
            "We track your physical location even when the app is closed. "
            "Subscriptions automatically renew unless cancelled. "
            "All disputes shall be resolved exclusively through confidential binding arbitration. "
            "You waive any right to participate in a class action. "
            "We reserve the right to modify these terms at any time without prior notice."
        )
        response = self.client.post("/api/scan", json={
            "text": high_risk_text,
            "document_name": "Test High Risk"
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data.get("risk_level"), "HIGH RISK")
        self.assertGreaterEqual(data.get("risk_score"), 68)
        self.assertGreaterEqual(data.get("red_flags"), 5)
        self.assertGreaterEqual(data.get("severity_counts", {}).get("HIGH", 0), 3)

    def test_scan_safe_policy_with_negation(self):
        """Verify scan on privacy-protective clauses with negation returns SAFE."""
        safe_text = (
            "AegisGuard operates as a local-first software utility. "
            "We do not use tracking cookies, device fingerprinting, analytics pixels, or session replay scripts. "
            "We do not collect location data, contact lists, or background sensor information. "
            "We do not sell, rent, monetize, or disclose personal data to advertisers. "
            "You retain full ownership and intellectual property rights in all data. "
            "We do not enforce mandatory binding arbitration or prohibit collective remedies."
        )
        response = self.client.post("/api/scan", json={
            "text": safe_text,
            "document_name": "Test Safe"
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data.get("risk_level"), "SAFE")
        self.assertLessEqual(data.get("risk_score"), 30)

    def test_static_routes(self):
        """Verify static pages are served correctly."""
        routes = ["/", "/scanner", "/results", "/history", "/about"]
        for route in routes:
            response = self.client.get(route)
            self.assertEqual(response.status_code, 200, f"Failed on route: {route}")
            self.assertIn("CorruptX", response.get_data(as_text=True))

if __name__ == "__main__":
    unittest.main()
