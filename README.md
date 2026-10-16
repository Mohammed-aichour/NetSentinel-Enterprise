# NetSentinel Enterprise — Next-Generation Network Security & Telemetry Monitoring Platform (NMS / SIEM)

[![CI/CD Tests](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/Mohammed-aichour/NetSentinel-Enterprise/actions)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/Security-MITRE%20ATT%26CK%20Aligned-crimson.svg)](https://attack.mitre.org/)
[![Docker Ready](https://img.shields.io/badge/docker-containerized-2496ED.svg)](Dockerfile)
[![Live SOC Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-success.svg)](https://mohammed-aichour.github.io/NetSentinel-Enterprise/)

> **NetSentinel Enterprise** is an enterprise-grade Network Management & Security Information and Event Management (NMS / SIEM) platform engineered for large-scale corporate data center and campus network infrastructures. Inspired by enterprise platforms like Zabbix, Wazuh, Prometheus, and Cisco DNA Center, it combines real-time network topology discovery, multi-protocol telemetry streaming, rule-based threat correlation, and stateful SOC incident orchestration into a unified cyber defense cockpit.

---

## 🌐 Live Interactive SOC Console Preview

Experience the real-time Cyber SOC Console directly in your browser:  
👉 **[Open Live NetSentinel SOC Dashboard](https://mohammed-aichour.github.io/NetSentinel-Enterprise/)**

*Includes interactive Canvas topology map, real-time telemetry streaming charts, and a built-in Cyber Attack Simulator.*

---

## 🏛️ Enterprise Multi-Tier Architecture

NetSentinel models and monitors an end-to-end corporate network topology across six distinct security tiers:

```mermaid
flowchart TD
    subgraph T0 ["Tier 0: Perimeter Edge Security"]
        FW1["Palo Alto PA-5450 (10.0.1.1)"]
        FW2["Fortinet FortiGate-3700F HA (10.0.1.2)"]
        RTR["Cisco ASR 9904 BGP Router (10.0.1.254)"]
    end

    subgraph T1 ["Tier 1: Core Distribution Backbone"]
        SW1["Cisco Nexus 9300 Spine 01 (10.0.2.1)"]
        SW2["Cisco Nexus 9300 Spine 02 (10.0.2.2)"]
    end

    subgraph T2 ["Tier 2: DMZ Public Services"]
        WAF["Nginx Reverse Proxy & WAF (10.0.3.10)"]
        VPN["WireGuard / OpenVPN Gateway (10.0.3.20)"]
    end

    subgraph T3 ["Tier 3: Enterprise Shared Services"]
        DC["Windows Server 2022 AD DC (10.0.4.10)"]
        SIEM["NetSentinel SOC Master (10.0.4.50)"]
    end

    subgraph T4 ["Tier 4: Mission-Critical Databases"]
        DB1["PostgreSQL 16 Primary (10.0.5.10)"]
        DB2["PostgreSQL 16 Replica (10.0.5.11)"]
    end

    subgraph T5 ["Tier 5: Campus Access & Endpoints"]
        SWL["Catalyst 9200 Floor 1 Switch (10.0.10.1)"]
        DEV["Engineer Workstation (10.0.10.105)"]
        CAM["Axis 4K Perimeter Camera (10.0.20.15)"]
    end

    RTR --- FW1 & FW2
    FW1 & FW2 --- SW1 & SW2
    SW1 --- SW2
    SW1 & SW2 --- WAF & VPN
    SW1 & SW2 --- DC & SIEM
    SW1 & SW2 --- DB1 & DB2
    DB1 --- DB2
    SW1 --- SWL
    SWL --- DEV & CAM
```

---

## ⚡ Core Capabilities

### 1. Multi-Protocol Telemetry Collector
* **Real ICMP Ping Engine:** Measures round-trip time (RTT), latency jitter, and interface packet loss.
* **TCP Socket Probes:** Verifies full 3-way handshakes against critical service ports (HTTP 80, HTTPS 443, SSH 22, DNS 53, PostgreSQL 5432).
* **Synthetic SNMP MIB-II Telemetry:** Simulates realistic stochastic bandwidth, CPU utilization, and packet rates tailored to each device's operational role.
* **Zero-External DB Dependency:** Persistent relational SQLite storage with Write-Ahead Logging (`WAL`) mode enabled.

### 2. SIEM Threat Correlation & MITRE ATT&CK Mapping
The correlation engine runs window-based behavioral analysis to detect multi-stage cyber attacks:

| Rule ID | Name | MITRE ATT&CK | Threshold / Trigger | Action |
| :--- | :--- | :--- | :--- | :--- |
| **`SEC-R001`** | **SSH Credential Brute-Force** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | > 5 failed auths in 60s | Alerts SOC & flags host |
| **`SEC-R002`** | **Horizontal Port Sweep** | [T1046](https://attack.mitre.org/techniques/T1046/) | > 12 unique ports in 30s | Escalates incident to HIGH |
| **`SEC-R003`** | **Volumetric DDoS / Traffic Anomaly** | [T1498.001](https://attack.mitre.org/techniques/T1498/001/) | > 3.0x baseline BW (>30k PPS) | Critical alert & auto-quarantine |
| **`SEC-R004`** | **Unauthorized Rogue MAC** | [T1200](https://attack.mitre.org/techniques/T1200/) | Unrecognized MAC on sensitive VLAN | High severity alert |
| **`SEC-R005`** | **Core Link Flapping** | `NMS-NET-01` | Packet loss burst > 5% | Operational warning |

### 3. Cyber SOC Console & Attack Simulator
* **Interactive Canvas Topology:** Node-link network map with dynamic traffic pulses, tier column alignments, hover tooltips, and click-to-inspect drawers.
* **Real-Time Streaming Charts:** Smooth SVG/Canvas area charts tracking aggregate throughput, average latency, and interface drops with zero external CDN dependencies.
* **Attack Simulator:** 1-click execution of DDoS surges, SSH brute-force attempts, reconnaissance scans, and backbone fiber failures to observe immediate SIEM alerting and state degradation.
* **Host Quarantine:** 1-click port/host network isolation that sets the target status to QUARANTINED and silences traffic.

---

## 🚀 Quickstart & Installation

### Prerequisites
* Python 3.10+ (tested on Python 3.11, 3.12, 3.13)
* Standard networking tools (`ping`, `curl`)

### Method 1: Local Python Environment
```bash
# 1. Clone the repository
git clone https://github.com/Mohammed-aichour/NetSentinel-Enterprise.git
cd NetSentinel-Enterprise

# 2. Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # On Linux/macOS
.\.venv\Scripts\Activate.ps1    # On Windows PowerShell

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start NetSentinel Server
python app.py
```
Open your browser at **`http://localhost:8080/`** to access the SOC Console.

### Method 2: Docker / Docker Compose
```bash
# Build and run containerized platform
docker-compose up -d

# Check running status and health probe
docker ps
```

---

## 🧪 Automated Test Suite

The test suite thoroughly verifies network probes, telemetry collectors, threat correlation heuristics, alert state transitions, and REST API endpoints:

```bash
# Run pytest with verbose test discovery
pytest -v
```

### Verified Test Matrix (18/18 Passing):
```
tests/test_alert_manager.py::TestAlertManager::test_alert_acknowledgment_and_resolution PASSED
tests/test_alert_manager.py::TestAlertManager::test_alert_processing_and_deduplication PASSED
tests/test_api.py::TestRestAPI::test_device_detail_endpoint PASSED
tests/test_api.py::TestRestAPI::test_device_probe_endpoint PASSED
tests/test_api.py::TestRestAPI::test_device_quarantine_toggle PASSED
tests/test_api.py::TestRestAPI::test_devices_listing_and_filtering PASSED
tests/test_api.py::TestRestAPI::test_health_endpoint PASSED
tests/test_api.py::TestRestAPI::test_simulation_attack_endpoint PASSED
tests/test_api.py::TestRestAPI::test_telemetry_live_endpoint PASSED
tests/test_api.py::TestRestAPI::test_topology_endpoint PASSED
tests/test_collector.py::TestNetworkCollector::test_local_telemetry_metrics PASSED
tests/test_collector.py::TestNetworkCollector::test_localhost_ping PASSED
tests/test_collector.py::TestNetworkCollector::test_quarantined_device_telemetry PASSED
tests/test_collector.py::TestNetworkCollector::test_synthetic_device_telemetry_firewall PASSED
tests/test_correlator.py::TestEventCorrelator::test_port_scan_detection PASSED
tests/test_correlator.py::TestEventCorrelator::test_ssh_brute_force_detection PASSED
tests/test_correlator.py::TestEventCorrelator::test_telemetry_threshold_alerts PASSED
tests/test_correlator.py::TestEventCorrelator::test_volumetric_ddos_detection PASSED

============================= 18 passed in 5.68s ==============================
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | System operational status, monitored node count, and health summary. |
| `GET` | `/api/v1/topology` | Returns network nodes and graph links organized by tier. |
| `GET` | `/api/v1/devices` | Returns inventory catalog with optional `tier`, `status`, and `q` search. |
| `GET` | `/api/v1/devices/<id>` | Full metadata, open services, and historical telemetry for a device. |
| `POST` | `/api/v1/devices/<id>/probe` | Executes live ICMP ping and service TCP port checks. |
| `POST` | `/api/v1/devices/<id>/quarantine` | Enforces or releases host network isolation. |
| `GET` | `/api/v1/telemetry/live` | Real-time aggregate cluster telemetry (In/Out Mbps, PPS, Latency). |
| `GET` | `/api/v1/alerts` | Active alerts with `status` and `severity` filters. |
| `POST` | `/api/v1/alerts/<id>/acknowledge` | SOC operator acknowledgment of an alert. |
| `POST` | `/api/v1/alerts/<id>/resolve` | Resolves alert with remediation audit notes. |
| `POST` | `/api/v1/simulation/attack` | Injects attack scenarios (`ddos`, `brute_force`, `port_scan`, `link_flap`). |

---

## 📁 Repository Structure

```
NetSentinel-Enterprise/
├── backend/
│   ├── app.py                 # Application server & web static proxy
│   ├── config.py              # System thresholds & MITRE rule constants
│   ├── database.py            # SQLite schema, WAL mode & repository methods
│   ├── engine/
│   │   ├── collector.py       # ICMP, TCP socket & SNMP telemetry collector
│   │   ├── correlator.py      # SIEM threat correlator (MITRE ATT&CK)
│   │   ├── alert_manager.py   # State machine, de-duplication & quarantine
│   │   └── simulator.py       # Topology seeder & cyber attack scenarios
│   ├── models/
│   │   └── schemas.py         # Domain dataclasses & serialization
│   └── routes/
│       └── api.py             # REST API Blueprint (/api/v1/...)
├── frontend/                  # Production SOC Web Application
│   ├── index.html             # Cyber SOC console layout
│   ├── css/soc.css            # Dark glassmorphism SOC theme
│   └── js/
│       ├── app.js             # State controller & API sync
│       ├── topology.js        # Interactive Canvas topology engine
│       └── charts.js          # Real-time streaming area charts
├── docs/                      # GitHub Pages deployment & documentation
│   ├── index.html             # Live interactive demo
│   ├── architecture.md        # Architectural specification
│   └── ...
├── tests/                     # Automated test suite
│   ├── test_collector.py
│   ├── test_correlator.py
│   ├── test_alert_manager.py
│   └── test_api.py
├── scripts/
│   ├── simulate_attack.py     # CLI attack simulation tool
│   └── seed_topology.py       # Topology database seeder
├── .github/workflows/ci.yml   # Multi-version CI & GitHub Pages CD
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── LICENSE
└── README.md
```

---

## 👤 Author & Attribution

**Mohammed Aichour**  
*Computer Science & Engineering Student — Universiapolis (Agadir, Morocco)*  
*Specialization: Cybersecurity, Network Infrastructure & Full-Stack Systems*  

* **GitHub:** [@Mohammed-aichour](https://github.com/Mohammed-aichour)
* **Portfolio:** [mohammed-aichour.github.io](https://mohammed-aichour.github.io/)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) — free for academic, enterprise, and educational use.
