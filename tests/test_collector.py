"""
Unit Tests for Telemetry Collector and Network Probes
"""

import unittest
from backend.engine.collector import NetworkProbe, TelemetryCollector


class TestNetworkCollector(unittest.TestCase):

    def test_localhost_ping(self):
        res = NetworkProbe.ping_host("127.0.0.1")
        self.assertIsInstance(res, dict)
        self.assertTrue(res["reachable"])
        self.assertGreaterEqual(res["rtt_ms"], 0.0)
        self.assertEqual(res["packet_loss_percent"], 0.0)
        self.assertEqual(res["status"], "REACHABLE")

    def test_unreachable_ping(self):
        # 192.0.2.1 is TEST-NET-1 (RFC 5737), non-routable dummy IP
        res = NetworkProbe.ping_host("192.0.2.1", timeout_ms=300)
        self.assertIsInstance(res, dict)
        self.assertFalse(res["reachable"])
        self.assertEqual(res["packet_loss_percent"], 100.0)
        self.assertIn(res["status"], ("TIMEOUT", "UNREACHABLE", "ERROR"))

    def test_tcp_port_probe_refused(self):
        # Port 65530 is almost certainly unused on loopback, should return REFUSED
        res = NetworkProbe.check_tcp_port("127.0.0.1", 65530, timeout_sec=0.2)
        self.assertIsInstance(res, dict)
        self.assertFalse(res["is_open"])
        self.assertIn(res["status"], ("REFUSED", "TIMED_OUT", "FAILED"))

    def test_local_telemetry_metrics(self):
        metrics = TelemetryCollector.get_local_system_telemetry()
        self.assertIn("cpu_percent", metrics)
        self.assertIn("memory_percent", metrics)
        self.assertIn("bandwidth_in_mbps", metrics)
        self.assertIn("packets_per_sec", metrics)
        self.assertIn("is_simulated", metrics)
        self.assertFalse(metrics["is_simulated"])  # Real host metrics
        self.assertGreaterEqual(metrics["cpu_percent"], 0.0)
        self.assertLessEqual(metrics["cpu_percent"], 100.0)

    def test_synthetic_device_telemetry_firewall(self):
        dev = {"id": "fw-edge-01", "role": "Next-Gen Firewall", "tier": "EDGE", "is_quarantined": False}
        sample = TelemetryCollector.sample_device_telemetry(dev)
        self.assertEqual(sample["device_id"], "fw-edge-01")
        self.assertTrue(sample["is_simulated"])  # Explicit simulation label
        self.assertGreater(sample["bandwidth_in_mbps"], 200.0)
        self.assertGreater(sample["packets_per_sec"], 5000)

    def test_quarantined_device_telemetry(self):
        dev = {"id": "ws-infected-01", "role": "Workstation", "tier": "ACCESS", "is_quarantined": True}
        sample = TelemetryCollector.sample_device_telemetry(dev)
        self.assertEqual(sample["packet_loss_percent"], 100.0)
        self.assertEqual(sample["bandwidth_in_mbps"], 0.0)
        self.assertEqual(sample["packets_per_sec"], 0)


if __name__ == "__main__":
    unittest.main()
