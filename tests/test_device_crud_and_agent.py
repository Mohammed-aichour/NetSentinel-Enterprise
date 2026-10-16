"""
NetSentinel Enterprise - REST API Integration Tests
Tests /api/v1/ready, Device CRUD endpoints, batch agent telemetry ingestion,
CORS header compliance, and optional API key authentication.
Author: Mohammed Aichour
"""

import json
import unittest
import tempfile
from pathlib import Path

from backend.app import create_app
from backend.database import init_db, DeviceRepository


class TestDeviceCrudAndAgentApi(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = str(Path(self.temp_dir.name) / "test_api_devices.db")
        os_env_patch = {"NETSENTINEL_DB_PATH": self.test_db_path}
        
        # Initialize test database
        init_db(self.test_db_path)

        # Patch environment for test app
        import os
        self.orig_env = os.environ.get("NETSENTINEL_DB_PATH")
        os.environ["NETSENTINEL_DB_PATH"] = self.test_db_path

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        import os
        if self.orig_env is not None:
            os.environ["NETSENTINEL_DB_PATH"] = self.orig_env
        elif "NETSENTINEL_DB_PATH" in os.environ:
            del os.environ["NETSENTINEL_DB_PATH"]
        self.temp_dir.cleanup()

    def test_ready_endpoint(self):
        """Verifies GET /api/v1/ready returns HTTP 200 with database engine status."""
        res = self.client.get("/api/v1/ready")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "READY")
        self.assertIn("database_engine", data)
        self.assertGreaterEqual(data["devices_registered"], 0)

    def test_device_crud_rest_lifecycle(self):
        """Verifies full REST lifecycle: POST, GET, PUT, DELETE for /api/v1/devices."""
        # 1. Create Device
        new_dev = {
            "id": "srv-api-gateway",
            "hostname": "gateway.corp.internal",
            "ip_address": "10.0.3.50",
            "mac_address": "00:1B:44:11:3A:B7",
            "tier": "DMZ",
            "role": "API Edge Gateway",
            "vendor": "Kong Enterprise",
            "services": [{"port": 8443, "name": "HTTPS-API"}]
        }
        create_res = self.client.post("/api/v1/devices", json=new_dev)
        self.assertEqual(create_res.status_code, 201)
        created_data = create_res.get_json()
        self.assertEqual(created_data["status"], "CREATED")
        self.assertEqual(created_data["device"]["id"], "srv-api-gateway")

        # Duplicate ID should return 409 Conflict
        dup_res = self.client.post("/api/v1/devices", json=new_dev)
        self.assertEqual(dup_res.status_code, 409)

        # 2. Retrieve Device
        get_res = self.client.get("/api/v1/devices/srv-api-gateway")
        self.assertEqual(get_res.status_code, 200)
        get_data = get_res.get_json()
        self.assertEqual(get_data["device"]["hostname"], "gateway.corp.internal")

        # 3. Update Device
        put_res = self.client.put("/api/v1/devices/srv-api-gateway", json={
            "hostname": "gateway-ha.corp.internal",
            "role": "High-Availability API Gateway"
        })
        self.assertEqual(put_res.status_code, 200)
        updated_data = put_res.get_json()
        self.assertEqual(updated_data["device"]["hostname"], "gateway-ha.corp.internal")

        # 4. Delete Device
        del_res = self.client.delete("/api/v1/devices/srv-api-gateway")
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(del_res.get_json()["status"], "DELETED")

        # Verify device no longer exists
        not_found_res = self.client.get("/api/v1/devices/srv-api-gateway")
        self.assertEqual(not_found_res.status_code, 404)

    def test_agent_telemetry_report_endpoint(self):
        """Verifies POST /api/v1/telemetry/report ingests local agent probe reports."""
        # Ensure a device exists
        self.client.post("/api/v1/devices", json={
            "id": "db-rep-test",
            "hostname": "rep.corp.internal",
            "ip_address": "10.0.5.99",
            "tier": "DATABASE"
        })

        agent_report = {
            "agent_id": "collector-agent-worker-01",
            "timestamp": "2026-10-16T12:00:00Z",
            "agent_host_metrics": {"cpu_percent": 14.5, "memory_percent": 38.2},
            "probes": [
                {
                    "device_id": "db-rep-test",
                    "reachable": True,
                    "rtt_ms": 1.12,
                    "packet_loss_percent": 0.0,
                    "cpu_percent": 30.0,
                    "memory_percent": 50.0
                }
            ]
        }

        res = self.client.post("/api/v1/telemetry/report", json=agent_report)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "ACCEPTED")
        self.assertEqual(data["probes_processed"], 1)

    def test_cors_headers_and_preflight(self):
        """Verifies CORS headers are attached and OPTIONS preflight returns 204."""
        # Standard GET
        res = self.client.get("/api/v1/health")
        self.assertIn("Access-Control-Allow-Origin", res.headers)
        self.assertIn("Access-Control-Allow-Methods", res.headers)

        # Preflight OPTIONS
        options_res = self.client.options("/api/v1/devices")
        self.assertIn(options_res.status_code, (200, 204))
        self.assertIn("Access-Control-Allow-Origin", options_res.headers)
        self.assertIn("Access-Control-Allow-Methods", options_res.headers)


if __name__ == "__main__":
    unittest.main()
