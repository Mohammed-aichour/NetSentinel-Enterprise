"""
Unit Tests for Alert Manager Lifecycle & State Transitions
"""

import unittest
import tempfile
import os
from backend.database import init_db, DeviceRepository
from backend.engine.alert_manager import AlertManager


class TestAlertManager(unittest.TestCase):

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db_path = self.temp_db.name
        init_db(self.db_path)

        # Seed test device
        DeviceRepository.upsert({
            "id": "fw-test-01",
            "hostname": "FW-TEST.corp.internal",
            "ip_address": "10.10.10.1",
            "mac_address": "00:11:22:33:44:55",
            "tier": "EDGE",
            "role": "Firewall",
            "vendor": "Cisco",
            "status": "ONLINE"
        }, db_path=self.db_path)

        self.alert_mgr = AlertManager(db_path=self.db_path)

    def tearDown(self):
        import gc
        gc.collect()
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except PermissionError:
                pass

    def test_alert_processing_and_deduplication(self):
        alert_data = {
            "id": "ALT-TEST-001",
            "device_id": "fw-test-01",
            "rule_id": "SEC-R001",
            "severity": "CRITICAL",
            "title": "Brute Force Attack",
            "message": "Multiple SSH failures detected."
        }

        # First alert should be processed
        processed = self.alert_mgr.process_incoming_alert(alert_data)
        self.assertIsNotNone(processed)

        # Duplicate alert with same device & rule should be de-duplicated / suppressed
        duplicate_data = dict(alert_data)
        duplicate_data["id"] = "ALT-TEST-002"
        duplicate_processed = self.alert_mgr.process_incoming_alert(duplicate_data)
        self.assertIsNone(duplicate_processed)

    def test_alert_acknowledgment_and_resolution(self):
        alert_data = {
            "id": "ALT-LIFE-001",
            "device_id": "fw-test-01",
            "rule_id": "SEC-R002",
            "severity": "HIGH",
            "title": "Port Scan Detected",
            "message": "Port sweep in progress."
        }
        self.alert_mgr.process_incoming_alert(alert_data)

        # Acknowledge
        ack_success = self.alert_mgr.acknowledge_alert("ALT-LIFE-001", operator="SOC-Mohammed")
        self.assertTrue(ack_success)

        # Resolve
        res_success = self.alert_mgr.resolve_alert("ALT-LIFE-001", resolution_note="Host IP blocked on edge ACL")
        self.assertTrue(res_success)


if __name__ == "__main__":
    unittest.main()
