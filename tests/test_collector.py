"""
Unit Tests for Telemetry Collector and Network Probes
"""

import unittest
from backend.engine.collector import NetworkProbe, TelemetryCollector


class TestNetworkCollector(unittest.TestCase):

    def test_localhost_ping(self):
        reachable, rtt, loss = NetworkProbe.ping_host("127.0.0.1")
        self.assertTrue(reachable)
        self.assertGreaterEqual(rtt, 0.0)
        self.assertEqual(loss, 0.0)

    def test_local_telemetry_metrics(self):
        metrics = TelemetryCollector.get_local_system_telemetry()
        self.assertIn("cpu_percent", metrics)
        self.assertIn("memory_percent", metrics)
        self.assertIn("bandwidth_in_mbps", metrics)
        self.assertIn("packets_per_sec", metrics)
        self.assertGreaterEqual(metrics["cpu_percent"], 0.0)
        self.assertLessEqual(metrics["cpu_percent"], 100.0)

    def test_synthetic_device_telemetry_firewall(self):
        dev = {"id": "fw-edge-01", "role": "Next-Gen Firewall", "tier": "EDGE", "is_quarantined": False}
        sample = TelemetryCollector.sample_device_telemetry(dev)
        self.assertEqual(sample["device_id"], "fw-edge-01")
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
