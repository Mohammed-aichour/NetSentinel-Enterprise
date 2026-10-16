"""
NetSentinel Enterprise - Core Domain Schemas & Serialization Models
Type definitions for Network Inventory, Telemetry, and SIEM Security Events.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


@dataclass
class ServicePort:
    port: int
    name: str
    status: str = "OPEN"  # OPEN, FILTERED, CLOSED
    version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Device:
    id: str
    hostname: str
    ip_address: str
    mac_address: str
    tier: str  # EDGE, CORE, DISTRIBUTION, DMZ, SERVICES, DATABASE, ACCESS
    role: str  # Firewall, Core Router, Agg Switch, Proxy, DC, DB, SIEM, Workstation
    vendor: str
    status: str = "ONLINE"  # ONLINE, DEGRADED, CRITICAL, OFFLINE
    services: List[Dict[str, Any]] = field(default_factory=list)
    is_quarantined: bool = False
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TelemetrySample:
    device_id: str
    cpu_percent: float
    memory_percent: float
    latency_ms: float
    packet_loss_percent: float
    bandwidth_in_mbps: float
    bandwidth_out_mbps: float
    packets_per_sec: int
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    id: str
    device_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    message: str
    rule_id: Optional[str] = None
    mitre_id: Optional[str] = None
    status: str = "NEW"  # NEW, ACKNOWLEDGED, RESOLVED, SUPPRESSED
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    acknowledged_at: Optional[str] = None
    resolved_at: Optional[str] = None
    resolution_note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityEvent:
    source_ip: str
    target_device_id: str
    event_type: str
    payload_summary: str
    severity: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TopologyLink:
    source_id: str
    target_id: str
    link_type: str = "10GbE-Trunk"
    bandwidth_mbps: int = 10000
    status: str = "UP"  # UP, DEGRADED, DOWN

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
