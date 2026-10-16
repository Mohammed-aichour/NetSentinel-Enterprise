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

    def test_all_simulation_scenarios(self):
        scenarios = ["brute_force", "port_scan", "link_flap", "rogue_mac"]
        for scen in scenarios:
            resp = self.client.post("/api/v1/simulation/attack", json={"attack_type": scen})
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertEqual(data["status"], "SUCCESS")
            self.assertIn("result", data)
            self.assertIn("scenario", data["result"])

    def test_events_ingest_and_retrieval(self):
        # Single event ingest
        single_ev = {
            "device_id": "fw-edge-01",
            "event_type": "FIREWALL_DROP",
            "source_ip": "10.99.99.1",
            "raw_message": "Packet dropped on eth0 by rule 42"
        }
        resp = self.client.post("/api/v1/events/ingest", json=single_ev)
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["ingested_count"], 1)

        # Batch ingest
        batch = [
            {"device_id": "db-core-01", "event_type": "AUTH_FAILURE", "source_ip": "10.0.0.5"},
            {"device_id": "db-core-01", "event_type": "AUTH_FAILURE", "source_ip": "10.0.0.5"}
        ]
        resp_batch = self.client.post("/api/v1/events/ingest", json=batch)
        self.assertEqual(resp_batch.status_code, 201)
        self.assertEqual(resp_batch.get_json()["ingested_count"], 2)

        # Retrieve events
        get_resp = self.client.get("/api/v1/events?limit=10")
        self.assertEqual(get_resp.status_code, 200)
        events_data = get_resp.get_json()
        self.assertIn("events", events_data)
        self.assertGreater(events_data["count"], 0)

    def test_audit_logs_endpoint(self):
        # Trigger quarantine to produce an audit entry
        self.client.post("/api/v1/devices/fw-edge-01/quarantine", json={"quarantine": True})
        self.client.post("/api/v1/devices/fw-edge-01/quarantine", json={"quarantine": False})

        resp = self.client.get("/api/v1/audit?limit=10")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("logs", data)
        self.assertGreater(data["count"], 0)
        first_entry = data["logs"][0]
        self.assertIn("action", first_entry)
        self.assertIn("operator", first_entry)

    def test_closed_loop_lifecycle(self):
        # 1. Trigger brute force attack against db-prod-pri
        attack_resp = self.client.post("/api/v1/simulation/attack", json={
            "attack_type": "brute_force",
            "target_id": "db-prod-pri"
        })
        self.assertEqual(attack_resp.status_code, 200)

        # 2. Verify device status degraded
        dev_resp = self.client.get("/api/v1/devices/db-prod-pri")
        self.assertEqual(dev_resp.status_code, 200)
        self.assertEqual(dev_resp.get_json()["device"]["status"], "CRITICAL")

        # 3. Find triggered alert
        alerts_resp = self.client.get("/api/v1/alerts?device_id=db-prod-pri&status=NEW")
        self.assertEqual(alerts_resp.status_code, 200)
        alerts = alerts_resp.get_json()["alerts"]
        self.assertGreater(len(alerts), 0)
        alert_id = alerts[0]["id"]

        # 4. Resolve alert
        res_resp = self.client.post(f"/api/v1/alerts/{alert_id}/resolve", json={"resolution_note": "Host patched"})
        self.assertEqual(res_resp.status_code, 200)

        # 5. Verify device health auto-recovered to ONLINE
        dev_recovered = self.client.get("/api/v1/devices/db-prod-pri").get_json()["device"]
        self.assertEqual(dev_recovered["status"], "ONLINE")


if __name__ == "__main__":
    unittest.main()



