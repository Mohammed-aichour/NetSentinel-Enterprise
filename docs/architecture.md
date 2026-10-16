# NetSentinel Enterprise — Architectural Specification & Engineering Design

## 1. System Overview

**NetSentinel Enterprise** is a high-throughput Network Security & Telemetry Monitoring System (NMS & SIEM) engineered to provide unified visibility, threat detection, and incident response for large-scale corporate enterprise infrastructures.

```mermaid
flowchart TD
    subgraph Infrastructure ["Monitored Multi-Tier Infrastructure"]
        Edge["Perimeter Tier\n(PA-5450 Firewalls, Cisco ASR BGP)"]
        Core["Core Spine Backbone\n(Cisco Nexus 9300 100GbE)"]
        DMZ["DMZ Tier\n(Nginx WAF, WireGuard VPN)"]
        Services["Corporate Services\n(Active Directory DC, DNS/DHCP)"]
        Database["Database Tier\n(PostgreSQL 16 HA Cluster)"]
        Access["Access VLANs\n(Catalyst 9200, Workstations, IoT)"]
    end

    subgraph Collection ["Multi-Protocol Telemetry Ingestion"]
        ICMP["ICMP Ping Probe\n(RTT & Packet Loss)"]
        TCP["TCP Socket Probe\n(3-Way Handshake)"]
        SNMP["SNMP MIB-II Engine\n(CPU, RAM, Bandwidth, PPS)"]
        Agent["REST API Ingestion\n(/api/v1/metrics/ingest)"]
    end

    subgraph Engine ["NetSentinel Core Processing Core"]
        Correlator["SIEM Event Correlator\n(MITRE ATT&CK Sliding Windows)"]
        AlertMgr["Stateful Alert Manager\n(De-duplication & Hysteresis)"]
        DB[(SQLite WAL Database\nTime-Series Persistence)]
    end

    subgraph Presentation ["Cyber SOC Dashboard & Automation"]
        WebUI["Interactive Canvas SOC UI\n(Live Topology & Telemetry Graphs)"]
        API["REST API Controller\n(/api/v1/...)"]
        Quarantine["Automated Quarantine\n(Host/Port Network Isolation)"]
    end

    Edge --> ICMP & TCP & SNMP
    Core --> ICMP & TCP & SNMP
    DMZ --> ICMP & TCP & SNMP
    Services --> ICMP & TCP & SNMP
    Database --> ICMP & TCP & SNMP
    Access --> ICMP & TCP & SNMP

    ICMP & TCP & SNMP & Agent --> Correlator
    Correlator --> AlertMgr
    AlertMgr --> DB
    AlertMgr --> Quarantine
    DB --> API
    API --> WebUI
```

---

## 2. SIEM Event Correlation Engine

The correlation engine maintains high-throughput in-memory sliding windows with automatic eviction. It maps behavioral anomalies directly to the **MITRE ATT&CK Matrix for Enterprise**:

| Rule ID | Threat Description | MITRE ID | Window | Threshold | Initial Severity |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC-R001` | SSH Credential Brute-Force | `T1110.001` | 60 sec | > 5 failed auths | `CRITICAL` |
| `SEC-R002` | Horizontal/Vertical Port Scan | `T1046` | 30 sec | > 12 unique ports | `HIGH` |
| `SEC-R003` | Volumetric DDoS / Traffic Anomaly | `T1498.001` | 30 sec | > 3.0x baseline BW or > 30k PPS | `CRITICAL` |
| `SEC-R004` | Rogue MAC on Sensitive VLAN | `T1200` | Real-time | ARP / MAC mismatch | `HIGH` |
| `SEC-R005` | Interface Flapping & Drop Burst | `NMS-NET-01` | 60 sec | > 4 state transitions | `MEDIUM` |

---

## 3. Stateful Alert Lifecycle & Incident State Machine

```mermaid
stateDiagram-v2
    [*] --> NEW: Event Correlated
    NEW --> ACKNOWLEDGED: SOC Analyst Takes Ownership
    ACKNOWLEDGED --> INVESTIGATING: Forensics / Packet Capture
    INVESTIGATING --> RESOLVED: Root Cause Remediated & Verified
    INVESTIGATING --> QUARANTINED: High Confidence Host Isolation
    QUARANTINED --> RESOLVED: Device Cleared & Restored
    NEW --> SUPPRESSED: False Positive / Maintenance Window
    RESOLVED --> [*]
```

---

## 4. Database Schema Design (SQLite WAL Mode)

- `devices`: Master registry of all switches, firewalls, and server nodes.
- `topology_links`: Relational graph edges with bandwidth and operational state.
- `telemetry_samples`: Indexed time-series samples (`device_id`, `timestamp DESC`).
- `alerts`: Deduplicated alert registry with MITRE mappings and operator audit notes.
- `security_events`: Raw security log stream ingested from agents and network taps.
- `audit_log`: Append-only compliance log recording every operator acknowledgment and remediation action.
