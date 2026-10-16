"""
Unit Tests for SIEM Event Correlator and Threat Detection
"""

import unittest
from backend.engine.correlator import EventCorrelator


class TestEventCorrelator(unittest.TestCase):

    def setUp(self):
        self.correlator = EventCorrelator()

    def test_ssh_brute_force_detection(self):
        target = "db-prod-pri"
        attacker = "192.168.1.150"

        # Record 3 failures (below threshold of 5)
        for _ in range(3):
            self.correlator.record_auth_event(attacker, target, success=False, protocol="SSH")
        alerts = self.correlator.check_brute_force()
        self.assertEqual(len(alerts), 0)

        # Record 3 more failures (total 6 -> exceeds threshold)
        for _ in range(3):
            self.correlator.record_auth_event(attacker, target, success=False, protocol="SSH")
        alerts = self.correlator.check_brute_force()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "CRITICAL")
        self.assertEqual(alerts[0]["rule_id"], "SEC-R001")
        self.assertEqual(alerts[0]["mitre_id"], "T1110.001")

    def test_port_scan_detection(self):
        target = "srv-proxy-01"
        attacker = "10.99.99.1"

        # Scan 14 distinct ports (threshold is 12)
        for p in range(20, 35):
            self.correlator.record_port_attempt(attacker, target, port=p)

        alerts = self.correlator.check_port_scan()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["rule_id"], "SEC-R002")
        self.assertEqual(alerts[0]["mitre_id"], "T1046")

    def test_volumetric_ddos_detection(self):
        normal_sample = {
            "device_id": "fw-edge-01",
            "bandwidth_in_mbps": 120.0,
            "packets_per_sec": 3500
        }
        self.assertIsNone(self.correlator.check_volumetric_ddos(normal_sample, baseline_bw=300.0))

        ddos_sample = {
            "device_id": "fw-edge-01",
            "bandwidth_in_mbps": 950.0,
            "packets_per_sec": 42000
        }
        alert = self.correlator.check_volumetric_ddos(ddos_sample, baseline_bw=300.0)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["rule_id"], "SEC-R003")

    def test_telemetry_threshold_alerts(self):
        sample = {
            "device_id": "sw-core-a",
            "cpu_percent": 98.0,
            "latency_ms": 250.0,
            "packet_loss_percent": 12.0
        }
        alerts = self.correlator.check_telemetry_thresholds(sample)
        self.assertEqual(len(alerts), 3)  # CPU critical, Latency critical, Loss critical
        for a in alerts:
            self.assertEqual(a["severity"], "CRITICAL")

    def test_rogue_mac_detection(self):
        target = "sw-core-a"
        # Authorized MAC should return None
        authorized_mac = "00:1A:A0:D4:02:01"
        self.assertIsNone(self.correlator.check_rogue_mac(target, authorized_mac))

        # Unknown / unauthorized MAC on sensitive VLAN should trigger SEC-R004
        unauthorized_mac = "B4:2E:99:AA:BB:CC"
        alert = self.correlator.check_rogue_mac(target, unauthorized_mac, vlan="VLAN-20-CORE")
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_id"], "SEC-R004")
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["mitre_id"], "T1200")

    def test_interface_flapping_detection(self):
        device = "sw-core-a"
        iface = "Te1/0/1"

        # Record 2 state transitions (below threshold of 4)
        self.correlator.record_link_transition(device, iface, "DOWN")
        self.correlator.record_link_transition(device, iface, "UP")
        self.assertEqual(len(self.correlator.check_interface_flapping()), 0)

        # Record 2 more state transitions (total 4 -> triggers threshold)
        self.correlator.record_link_transition(device, iface, "DOWN")
        self.correlator.record_link_transition(device, iface, "UP")
        alerts = self.correlator.check_interface_flapping()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "SEC-R005")
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertIn("Te1/0/1", alerts[0]["message"])


if __name__ == "__main__":
    unittest.main()
