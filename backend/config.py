"""
NetSentinel Enterprise - System Configuration & Enterprise Topology Constants
Author: Mohammed Aichour
Enterprise Network Security & Telemetry Monitoring Platform
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = os.getenv("NETSENTINEL_DB_PATH", str(DATA_DIR / "netsentinel.db"))

# Server Settings
HOST = os.getenv("NETSENTINEL_HOST", "0.0.0.0")
PORT = int(os.getenv("NETSENTINEL_PORT", "8080"))
DEBUG = os.getenv("NETSENTINEL_DEBUG", "false").lower() in ("true", "1", "yes")
SECRET_KEY = os.getenv("NETSENTINEL_SECRET", "netsentinel-enterprise-soc-token-2026")

# Telemetry & Polling Settings
POLL_INTERVAL_SECONDS = int(os.getenv("NETSENTINEL_POLL_INTERVAL", "5"))
TELEMETRY_RETENTION_POINTS = int(os.getenv("NETSENTINEL_HISTORY_LIMIT", "120"))
ICMP_TIMEOUT_MS = int(os.getenv("NETSENTINEL_ICMP_TIMEOUT_MS", "1500"))
TCP_TIMEOUT_SECONDS = float(os.getenv("NETSENTINEL_TCP_TIMEOUT_S", "1.5"))

# Thresholds for Telemetry Alerts
THRESHOLDS = {
    "cpu_high": 85.0,        # %
    "cpu_critical": 95.0,    # %
    "memory_high": 85.0,     # %
    "memory_critical": 95.0, # %
    "latency_high": 80.0,    # ms
    "latency_critical": 200.0,# ms
    "packet_loss_warning": 2.0, # %
    "packet_loss_critical": 8.0 # %
}

# Detection Rules Configuration (MITRE ATT&CK Mapping)
DETECTION_RULES = {
    "BRUTE_FORCE_SSH": {
        "id": "SEC-R001",
        "name": "SSH Credential Brute-Force",
        "mitre_id": "T1110.001",
        "mitre_tactic": "Credential Access",
        "threshold_attempts": 5,
        "window_seconds": 60,
        "severity": "CRITICAL"
    },
    "SYN_PORT_SCAN": {
        "id": "SEC-R002",
        "name": "Horizontal/Vertical Port Sweep",
        "mitre_id": "T1046",
        "mitre_tactic": "Discovery",
        "threshold_ports": 12,
        "window_seconds": 30,
        "severity": "HIGH"
    },
    "VOLUMETRIC_DDOS": {
        "id": "SEC-R003",
        "name": "Volumetric Traffic Anomaly (DDoS Spike)",
        "mitre_id": "T1498.001",
        "mitre_tactic": "Impact",
        "threshold_multiplier": 3.0,
        "window_seconds": 30,
        "severity": "CRITICAL"
    },
    "ROGUE_MAC_DETECTED": {
        "id": "SEC-R004",
        "name": "Unauthorized Rogue MAC on Sensitive VLAN",
        "mitre_id": "T1200",
        "mitre_tactic": "Initial Access",
        "severity": "HIGH"
    },
    "INTERFACE_FLAPPING": {
        "id": "SEC-R005",
        "name": "Interface Link State Flapping",
        "mitre_id": "NMS-NET-01",
        "mitre_tactic": "Operational Stability",
        "threshold_transitions": 4,
        "window_seconds": 60,
        "severity": "MEDIUM"
    }
}

# Enterprise Meta
ENTERPRISE_NAME = "UniversiaCorp Global Infrastructure"
SOC_NAME = "Cyber Defense Operations Center (CDOC)"
VERSION = "2.4.0-Enterprise"
