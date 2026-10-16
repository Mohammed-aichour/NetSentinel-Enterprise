"""
NetSentinel Enterprise - SIEM Threat Correlator & Anomaly Detection Engine
Evaluates telemetry streams and raw security logs against MITRE ATT&CK heuristics.
"""

import uuid
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from backend.config import DETECTION_RULES, THRESHOLDS

logger = logging.getLogger("netsentinel.correlator")


class EventCorrelator:
    """
    Correlates operational telemetry and security event logs to detect
    complex multi-stage network attacks and infrastructure anomalies.
    """

    def __init__(self):
        # In-memory sliding windows for high-throughput stream processing
        self._auth_failures: List[Dict[str, Any]] = []
        self._port_attempts: List[Dict[str, Any]] = []
        self._baseline_history: Dict[str, List[float]] = defaultdict(list)

    def record_auth_event(self, source_ip: str, target_device_id: str, success: bool, protocol: str = "SSH") -> None:
        """Records an authentication attempt in the sliding window."""
        if not success:
            self._auth_failures.append({
                "source_ip": source_ip,
                "target_device_id": target_device_id,
                "protocol": protocol,
                "timestamp": datetime.now(timezone.utc)
            })
            self._clean_old_events()

    def record_port_attempt(self, source_ip: str, target_device_id: str, port: int) -> None:
        """Records a TCP connection or SYN probe in the sliding window."""
        self._port_attempts.append({
            "source_ip": source_ip,
            "target_device_id": target_device_id,
            "port": port,
            "timestamp": datetime.now(timezone.utc)
        })
        self._clean_old_events()

    def _clean_old_events(self, max_age_seconds: int = 120) -> None:
        """Evicts expired events outside the correlation window."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
        self._auth_failures = [e for e in self._auth_failures if e["timestamp"] > cutoff]
        self._port_attempts = [e for e in self._port_attempts if e["timestamp"] > cutoff]

    def check_brute_force(self) -> List[Dict[str, Any]]:
        """
        Evaluates sliding window for SSH / RDP credential brute-forcing.
        Rule: SEC-R001 / MITRE T1110.001
        """
        rule = DETECTION_RULES["BRUTE_FORCE_SSH"]
        threshold = rule["threshold_attempts"]
        window_sec = rule["window_seconds"]
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_sec)

        counts = defaultdict(int)
        for ev in self._auth_failures:
            if ev["timestamp"] >= cutoff:
                key = (ev["source_ip"], ev["target_device_id"], ev["protocol"])
                counts[key] += 1

        alerts = []
        for (src_ip, target_id, protocol), fail_count in counts.items():
            if fail_count >= threshold:
                alert_id = f"ALT-BF-{uuid.uuid4().hex[:8].upper()}"
                alerts.append({
                    "id": alert_id,
                    "device_id": target_id,
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "title": f"{rule['name']} Detected",
                    "message": (
                        f"Detected {fail_count} failed {protocol} login attempts from "
                        f"unauthorized IP {src_ip} within {window_sec}s. Target: {target_id}."
                    ),
                    "mitre_id": rule["mitre_id"],
                    "status": "NEW",
                    "created_at": datetime.now(timezone.utc).isoformat()
                })
        return alerts

    def check_port_scan(self) -> List[Dict[str, Any]]:
        """
        Evaluates sliding window for horizontal or vertical port sweeps.
        Rule: SEC-R002 / MITRE T1046
        """
        rule = DETECTION_RULES["SYN_PORT_SCAN"]
        threshold_ports = rule["threshold_ports"]
        window_sec = rule["window_seconds"]
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_sec)

        probed_ports = defaultdict(set)
        for ev in self._port_attempts:
            if ev["timestamp"] >= cutoff:
                key = (ev["source_ip"], ev["target_device_id"])
                probed_ports[key].add(ev["port"])

        alerts = []
        for (src_ip, target_id), ports in probed_ports.items():
            if len(ports) >= threshold_ports:
                alert_id = f"ALT-SCAN-{uuid.uuid4().hex[:8].upper()}"
                sample_ports = sorted(list(ports))[:6]
                alerts.append({
                    "id": alert_id,
                    "device_id": target_id,
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "title": f"{rule['name']} In Progress",
                    "message": (
                        f"Hostile port scan detected from {src_ip} targeting {target_id}. "
                        f"{len(ports)} unique ports scanned in {window_sec}s (e.g. {sample_ports})."
                    ),
                    "mitre_id": rule["mitre_id"],
                    "status": "NEW",
                    "created_at": datetime.now(timezone.utc).isoformat()
                })
        return alerts

    def check_volumetric_ddos(self, sample: Dict[str, Any], baseline_bw: float = 300.0) -> Optional[Dict[str, Any]]:
        """
        Detects sudden volumetric bandwidth / PPS anomalies exceeding 3x the baseline.
        Rule: SEC-R003 / MITRE T1498.001
        """
        rule = DETECTION_RULES["VOLUMETRIC_DDOS"]
        bw_in = sample.get("bandwidth_in_mbps", 0.0)
        pps = sample.get("packets_per_sec", 0)

        # Trigger if bandwidth exceeds multiplier * baseline or PPS spikes over 30,000
        if bw_in >= (baseline_bw * rule["threshold_multiplier"]) or pps > 30000:
            alert_id = f"ALT-DDOS-{uuid.uuid4().hex[:8].upper()}"
            return {
                "id": alert_id,
                "device_id": sample["device_id"],
                "rule_id": rule["id"],
                "severity": rule["severity"],
                "title": f"{rule['name']} Alert",
                "message": (
                    f"Traffic surge on {sample['device_id']}: Inbound throughput spiked to {bw_in} Mbps "
                    f"with {pps:,} packets/sec ({round(bw_in / baseline_bw, 1)}x standard baseline)."
                ),
                "mitre_id": rule["mitre_id"],
                "status": "NEW",
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        return None

    def check_telemetry_thresholds(self, sample: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates operational health metrics (CPU, RAM, latency, packet drops).
        Produces structured NMS alerts.
        """
        alerts = []
        dev_id = sample["device_id"]
        cpu = sample.get("cpu_percent", 0.0)
        mem = sample.get("memory_percent", 0.0)
        lat = sample.get("latency_ms", 0.0)
        loss = sample.get("packet_loss_percent", 0.0)

        # CPU Threshold
        if cpu >= THRESHOLDS["cpu_critical"]:
            alerts.append({
                "id": f"ALT-CPU-{uuid.uuid4().hex[:8].upper()}",
                "device_id": dev_id,
                "rule_id": "NMS-CPU-01",
                "severity": "CRITICAL",
                "title": f"Critical CPU Utilization on {dev_id}",
                "message": f"Core processor load reached {cpu}% (Threshold: {THRESHOLDS['cpu_critical']}%).",
                "mitre_id": "NMS-HEALTH",
                "status": "NEW",
                "created_at": datetime.now(timezone.utc).isoformat()
            })
        elif cpu >= THRESHOLDS["cpu_high"]:
            alerts.append({
                "id": f"ALT-CPU-{uuid.uuid4().hex[:8].upper()}",
                "device_id": dev_id,
                "rule_id": "NMS-CPU-02",
                "severity": "HIGH",
                "title": f"High CPU Warning on {dev_id}",
                "message": f"Processor load elevated to {cpu}% (Warning: {THRESHOLDS['cpu_high']}%).",
                "mitre_id": "NMS-HEALTH",
                "status": "NEW",
                "created_at": datetime.now(timezone.utc).isoformat()
            })

        # Latency Threshold
        if lat >= THRESHOLDS["latency_critical"]:
            alerts.append({
                "id": f"ALT-LAT-{uuid.uuid4().hex[:8].upper()}",
                "device_id": dev_id,
                "rule_id": "NMS-LAT-01",
                "severity": "CRITICAL",
                "title": f"Severe Network Latency Degradation on {dev_id}",
                "message": f"Round-trip latency degraded to {lat}ms (Critical threshold: {THRESHOLDS['latency_critical']}ms).",
                "mitre_id": "NMS-HEALTH",
                "status": "NEW",
                "created_at": datetime.now(timezone.utc).isoformat()
            })

        # Packet Loss Threshold
        if loss >= THRESHOLDS["packet_loss_critical"]:
            alerts.append({
                "id": f"ALT-LOSS-{uuid.uuid4().hex[:8].upper()}",
                "device_id": dev_id,
                "rule_id": "NMS-LOSS-01",
                "severity": "CRITICAL",
                "title": f"Critical Packet Drop Rate on {dev_id}",
                "message": f"Interface packet loss measured at {loss}% (Critical limit: {THRESHOLDS['packet_loss_critical']}%).",
                "mitre_id": "NMS-HEALTH",
                "status": "NEW",
                "created_at": datetime.now(timezone.utc).isoformat()
            })

        return alerts
