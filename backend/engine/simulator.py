"""
NetSentinel Enterprise - Topology Seeder & SOC Cyber Attack Simulator
Initializes realistic multi-tier corporate network infrastructure and generates live attack scenarios.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from backend.database import get_connection, DeviceRepository, AlertRepository
from backend.models.schemas import Device, TopologyLink
from backend.engine.correlator import EventCorrelator
from backend.engine.alert_manager import AlertManager

logger = logging.getLogger("netsentinel.simulator")


ENTERPRISE_DEVICES: List[Dict[str, Any]] = [
    # Tier 0: Perimeter Edge
    {
        "id": "fw-edge-01",
        "hostname": "FW-EDGE-P1.corp.internal",
        "ip_address": "10.0.1.1",
        "mac_address": "00:1B:17:A1:01:01",
        "tier": "EDGE",
        "role": "Next-Gen Firewall",
        "vendor": "Palo Alto PAN-OS 11.1",
        "status": "ONLINE",
        "services": [{"port": 443, "name": "PAN-OS WebUI", "status": "OPEN"}, {"port": 22, "name": "SSH", "status": "OPEN"}]
    },
    {
        "id": "fw-edge-02",
        "hostname": "FW-EDGE-P2-HA.corp.internal",
        "ip_address": "10.0.1.2",
        "mac_address": "00:1B:17:A1:01:02",
        "tier": "EDGE",
        "role": "Next-Gen Firewall HA",
        "vendor": "Fortinet FortiGate-3700F",
        "status": "ONLINE",
        "services": [{"port": 443, "name": "FortiManager", "status": "OPEN"}]
    },
    {
        "id": "rtr-border-01",
        "hostname": "RTR-BGP-CORE.corp.internal",
        "ip_address": "10.0.1.254",
        "mac_address": "00:22:BD:C0:01:FE",
        "tier": "EDGE",
        "role": "Border BGP Router",
        "vendor": "Cisco ASR 9904 (IOS-XR)",
        "status": "ONLINE",
        "services": [{"port": 179, "name": "BGP", "status": "OPEN"}, {"port": 22, "name": "SSH-Admin", "status": "OPEN"}]
    },

    # Tier 1: Core Distribution Backbone
    {
        "id": "sw-core-a",
        "hostname": "SW-CORE-SPINE-01.corp.internal",
        "ip_address": "10.0.2.1",
        "mac_address": "00:1A:A0:D4:02:01",
        "tier": "CORE",
        "role": "Spine Switch 01",
        "vendor": "Cisco Nexus 9300-GX",
        "status": "ONLINE",
        "services": [{"port": 22, "name": "SSH", "status": "OPEN"}, {"port": 161, "name": "SNMPv3", "status": "OPEN"}]
    },
    {
        "id": "sw-core-b",
        "hostname": "SW-CORE-SPINE-02.corp.internal",
        "ip_address": "10.0.2.2",
        "mac_address": "00:1A:A0:D4:02:02",
        "tier": "CORE",
        "role": "Spine Switch 02",
        "vendor": "Cisco Nexus 9300-GX",
        "status": "ONLINE",
        "services": [{"port": 22, "name": "SSH", "status": "OPEN"}, {"port": 161, "name": "SNMPv3", "status": "OPEN"}]
    },

    # Tier 2: DMZ Zone
    {
        "id": "srv-proxy-01",
        "hostname": "DMZ-WAF-PROXY01.corp.internal",
        "ip_address": "10.0.3.10",
        "mac_address": "52:54:00:8C:03:0A",
        "tier": "DMZ",
        "role": "Reverse Proxy & WAF",
        "vendor": "Nginx Enterprise / ModSecurity",
        "status": "ONLINE",
        "services": [{"port": 80, "name": "HTTP", "status": "OPEN"}, {"port": 443, "name": "HTTPS/TLS", "status": "OPEN"}]
    },
    {
        "id": "srv-vpn-gw",
        "hostname": "DMZ-VPN-GATEWAY.corp.internal",
        "ip_address": "10.0.3.20",
        "mac_address": "52:54:00:8C:03:14",
        "tier": "DMZ",
        "role": "VPN Gateway",
        "vendor": "WireGuard / OpenVPN Enterprise",
        "status": "ONLINE",
        "services": [{"port": 1194, "name": "OpenVPN-TLS", "status": "OPEN"}, {"port": 51820, "name": "WireGuard", "status": "OPEN"}]
    },

    # Tier 3: Corporate Directory & Security Services
    {
        "id": "srv-ad-dc01",
        "hostname": "DC01-PRIMARY.corp.internal",
        "ip_address": "10.0.4.10",
        "mac_address": "00:0C:29:4F:04:0A",
        "tier": "SERVICES",
        "role": "Active Directory DC & Kerberos",
        "vendor": "Windows Server 2022 Datacenter",
        "status": "ONLINE",
        "services": [
            {"port": 53, "name": "DNS", "status": "OPEN"},
            {"port": 88, "name": "Kerberos", "status": "OPEN"},
            {"port": 389, "name": "LDAP", "status": "OPEN"},
            {"port": 445, "name": "SMBv3", "status": "OPEN"}
        ]
    },
    {
        "id": "srv-siem-01",
        "hostname": "NETSENTINEL-SOC01.corp.internal",
        "ip_address": "10.0.4.50",
        "mac_address": "52:54:00:E1:04:32",
        "tier": "SERVICES",
        "role": "SIEM & Telemetry Collector",
        "vendor": "NetSentinel Enterprise Engine",
        "status": "ONLINE",
        "services": [{"port": 8080, "name": "NetSentinel SOC Console", "status": "OPEN"}, {"port": 514, "name": "Syslog UDP", "status": "OPEN"}]
    },

    # Tier 4: Mission-Critical Database Storage
    {
        "id": "db-prod-pri",
        "hostname": "PG-CLUSTER-MASTER.corp.internal",
        "ip_address": "10.0.5.10",
        "mac_address": "00:50:56:B2:05:0A",
        "tier": "DATABASE",
        "role": "Primary Database Node",
        "vendor": "PostgreSQL 16 High-Availability",
        "status": "ONLINE",
        "services": [{"port": 5432, "name": "PostgreSQL", "status": "OPEN"}, {"port": 22, "name": "SSH", "status": "OPEN"}]
    },
    {
        "id": "db-prod-rep",
        "hostname": "PG-CLUSTER-REPLICA.corp.internal",
        "ip_address": "10.0.5.11",
        "mac_address": "00:50:56:B2:05:0B",
        "tier": "DATABASE",
        "role": "Database Replica / Standby",
        "vendor": "PostgreSQL 16 Streaming Replica",
        "status": "ONLINE",
        "services": [{"port": 5432, "name": "PostgreSQL-Read", "status": "OPEN"}, {"port": 22, "name": "SSH", "status": "OPEN"}]
    },

    # Tier 5: Campus Access Network & Endpoints
    {
        "id": "sw-access-fl1",
        "hostname": "SW-LEAF-FLOOR1.corp.internal",
        "ip_address": "10.0.10.1",
        "mac_address": "00:1E:F7:61:0A:01",
        "tier": "ACCESS",
        "role": "Floor 1 Access Switch",
        "vendor": "Cisco Catalyst 9200-48P",
        "status": "ONLINE",
        "services": [{"port": 22, "name": "SSH", "status": "OPEN"}]
    },
    {
        "id": "ws-eng-dev01",
        "hostname": "WS-DEV-MOHAMMED.corp.internal",
        "ip_address": "10.0.10.105",
        "mac_address": "00:28:F8:8C:0A:69",
        "tier": "ACCESS",
        "role": "Cyber Engineer Workstation",
        "vendor": "Ubuntu Desktop 24.04 LTS",
        "status": "ONLINE",
        "services": [{"port": 22, "name": "SSH", "status": "OPEN"}]
    },
    {
        "id": "iot-cam-gate",
        "hostname": "CAM-MAIN-ENTRANCE.iot.internal",
        "ip_address": "10.0.20.15",
        "mac_address": "AC:CC:8E:55:14:0F",
        "tier": "ACCESS",
        "role": "IP Security Camera",
        "vendor": "Axis Communications 4K H.265",
        "status": "ONLINE",
        "services": [{"port": 554, "name": "RTSP", "status": "OPEN"}, {"port": 80, "name": "HTTP", "status": "OPEN"}]
    }
]

TOPOLOGY_LINKS = [
    # Perimeter to Backbone
    {"source_id": "rtr-border-01", "target_id": "fw-edge-01", "link_type": "100GbE-Fiber", "bandwidth_mbps": 100000, "status": "UP"},
    {"source_id": "rtr-border-01", "target_id": "fw-edge-02", "link_type": "100GbE-Fiber", "bandwidth_mbps": 100000, "status": "UP"},
    {"source_id": "fw-edge-01", "target_id": "sw-core-a", "link_type": "40GbE-QSFP", "bandwidth_mbps": 40000, "status": "UP"},
    {"source_id": "fw-edge-02", "target_id": "sw-core-b", "link_type": "40GbE-QSFP", "bandwidth_mbps": 40000, "status": "UP"},
    
    # Core Interconnect
    {"source_id": "sw-core-a", "target_id": "sw-core-b", "link_type": "100GbE-PortChannel", "bandwidth_mbps": 200000, "status": "UP"},

    # DMZ Links
    {"source_id": "sw-core-a", "target_id": "srv-proxy-01", "link_type": "10GbE-Trunk", "bandwidth_mbps": 10000, "status": "UP"},
    {"source_id": "sw-core-b", "target_id": "srv-vpn-gw", "link_type": "10GbE-Trunk", "bandwidth_mbps": 10000, "status": "UP"},

    # Shared Services & SIEM
    {"source_id": "sw-core-a", "target_id": "srv-ad-dc01", "link_type": "10GbE-Direct", "bandwidth_mbps": 10000, "status": "UP"},
    {"source_id": "sw-core-b", "target_id": "srv-siem-01", "link_type": "10GbE-Direct", "bandwidth_mbps": 10000, "status": "UP"},

    # Database Cluster
    {"source_id": "sw-core-a", "target_id": "db-prod-pri", "link_type": "25GbE-Storage", "bandwidth_mbps": 25000, "status": "UP"},
    {"source_id": "sw-core-b", "target_id": "db-prod-rep", "link_type": "25GbE-Storage", "bandwidth_mbps": 25000, "status": "UP"},
    {"source_id": "db-prod-pri", "target_id": "db-prod-rep", "link_type": "25GbE-Replication", "bandwidth_mbps": 25000, "status": "UP"},

    # Access Switches & Endpoints
    {"source_id": "sw-core-a", "target_id": "sw-access-fl1", "link_type": "10GbE-Uplink", "bandwidth_mbps": 10000, "status": "UP"},
    {"source_id": "sw-access-fl1", "target_id": "ws-eng-dev01", "link_type": "1GbE-Access", "bandwidth_mbps": 1000, "status": "UP"},
    {"source_id": "sw-access-fl1", "target_id": "iot-cam-gate", "link_type": "PoE+-Access", "bandwidth_mbps": 1000, "status": "UP"}
]


def seed_enterprise_topology(db_path: Optional[str] = None) -> None:
    """Populates the database with the baseline corporate enterprise infrastructure."""
    with get_connection(db_path) as conn:
        # Seed Devices
        for dev in ENTERPRISE_DEVICES:
            DeviceRepository.upsert(dev, db_path=db_path)

        # Seed Links
        for link in TOPOLOGY_LINKS:
            conn.execute("""
                INSERT OR IGNORE INTO topology_links (source_id, target_id, link_type, bandwidth_mbps, status)
                VALUES (?, ?, ?, ?, ?)
            """, (link["source_id"], link["target_id"], link["link_type"], link["bandwidth_mbps"], link["status"]))
        conn.commit()
    logger.info("Enterprise topology seeded successfully.")


class CyberAttackSimulator:
    """
    Simulates high-fidelity real-world cyber attack scenarios to validate
    detection rules, alert escalation, and operator incident workflows.
    """

    def __init__(self, correlator: EventCorrelator, alert_manager: AlertManager):
        self.correlator = correlator
        self.alert_manager = alert_manager

    def trigger_ddos_spike(self, target_id: str = "fw-edge-01") -> Dict[str, Any]:
        """Simulates a volumetric SYN flood / UDP reflection assault."""
        sample = {
            "device_id": target_id,
            "bandwidth_in_mbps": 894.5,
            "bandwidth_out_mbps": 680.0,
            "packets_per_sec": 48250,
            "cpu_percent": 96.8,
            "memory_percent": 88.5,
            "latency_ms": 195.4,
            "packet_loss_percent": 7.8
        }
        alert = self.correlator.check_volumetric_ddos(sample)
        if alert:
            self.alert_manager.process_incoming_alert(alert)
        return {"scenario": "VOLUMETRIC_DDOS", "target": target_id, "alert_triggered": bool(alert), "telemetry": sample}

    def trigger_ssh_brute_force(self, target_id: str = "db-prod-pri", attacker_ip: str = "185.220.101.42") -> Dict[str, Any]:
        """Simulates 8 rapid failed SSH logins triggering T1110.001."""
        for _ in range(8):
            self.correlator.record_auth_event(attacker_ip, target_id, success=False, protocol="SSH")
        alerts = self.correlator.check_brute_force()
        for alt in alerts:
            self.alert_manager.process_incoming_alert(alt)
        return {"scenario": "SSH_BRUTE_FORCE", "target": target_id, "attacker_ip": attacker_ip, "alerts": alerts}

    def trigger_port_scan(self, target_id: str = "srv-proxy-01", attacker_ip: str = "194.26.29.112") -> Dict[str, Any]:
        """Simulates horizontal port sweep across 18 ports triggering T1046."""
        for p in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]:
            self.correlator.record_port_attempt(attacker_ip, target_id, port=p)
        alerts = self.correlator.check_port_scan()
        for alt in alerts:
            self.alert_manager.process_incoming_alert(alt)
        return {"scenario": "SYN_PORT_SCAN", "target": target_id, "attacker_ip": attacker_ip, "alerts": alerts}

    def trigger_link_flap(self, device_id: str = "sw-core-a") -> Dict[str, Any]:
        """Simulates switch core fiber link instability with elevated packet loss."""
        sample = {
            "device_id": device_id,
            "cpu_percent": 74.0,
            "memory_percent": 55.0,
            "latency_ms": 215.0,
            "packet_loss_percent": 12.5,
            "bandwidth_in_mbps": 140.0,
            "bandwidth_out_mbps": 110.0,
            "packets_per_sec": 8400
        }
        alerts = self.correlator.check_telemetry_thresholds(sample)
        for alt in alerts:
            self.alert_manager.process_incoming_alert(alt)
        return {"scenario": "LINK_FLAP", "target": device_id, "alerts": alerts}
