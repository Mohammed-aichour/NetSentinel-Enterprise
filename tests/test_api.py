"""
Integration Tests for REST API Endpoints
"""

import unittest
import json
from backend.app import create_app


class TestRestAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def test_health_endpoint(self):
        resp = self.client.get("/api/v1/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "HEALTHY")
        self.assertIn("stats", data)
        self.assertGreater(data["stats"]["total_devices"], 0)

    def test_topology_endpoint(self):
        resp = self.client.get("/api/v1/topology")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("nodes", data)
        self.assertIn("links", data)
        self.assertGreater(len(data["nodes"]), 5)
        self.assertGreater(len(data["links"]), 5)

    def test_devices_listing_and_filtering(self):
        resp = self.client.get("/api/v1/devices?tier=EDGE")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertGreater(data["count"], 0)
        for d in data["devices"]:
            self.assertEqual(d["tier"], "EDGE")

    def test_device_detail_endpoint(self):
        resp = self.client.get("/api/v1/devices/fw-edge-01")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["device"]["id"], "fw-edge-01")

    def test_device_probe_endpoint(self):
        resp = self.client.post("/api/v1/devices/fw-edge-01/probe")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("icmp", data)
        self.assertIn("services", data)

    def test_device_quarantine_toggle(self):
        resp = self.client.post("/api/v1/devices/fw-edge-01/quarantine", json={"quarantine": True})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["is_quarantined"])

        # Reset quarantine
        reset_resp = self.client.post("/api/v1/devices/fw-edge-01/quarantine", json={"quarantine": False})
        self.assertEqual(reset_resp.status_code, 200)

    def test_telemetry_live_endpoint(self):
        resp = self.client.get("/api/v1/telemetry/live")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("cluster_summary", data)
        self.assertIn("samples", data)

    def test_simulation_attack_endpoint(self):
        resp = self.client.post("/api/v1/simulation/attack", json={
            "attack_type": "ddos",
            "target_id": "fw-edge-01"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "SUCCESS")


if __name__ == "__main__":
    unittest.main()
