# NetSentinel Enterprise — Next-Generation Network Security & Telemetry Monitoring Platform (NMS / SIEM)

[![CI/CD Tests](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/Mohammed-aichour/NetSentinel-Enterprise/actions)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/Security-MITRE%20ATT%26CK%20Aligned-crimson.svg)](https://attack.mitre.org/)
[![Docker Ready](https://img.shields.io/badge/docker-containerized-2496ED.svg)](Dockerfile)
[![Vercel Ready](https://img.shields.io/badge/Vercel-Serverless%20%2B%20Postgres-black.svg)](vercel.json)
[![Live SOC Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-success.svg)](https://mohammed-aichour.github.io/NetSentinel-Enterprise/)

> **NetSentinel Enterprise** is an enterprise-grade Network Management & Security Information and Event Management (NMS / SIEM) platform engineered for corporate data center and campus network infrastructures. Inspired by enterprise systems like Zabbix, Wazuh, Prometheus, and Cisco DNA Center, it combines real-time network topology discovery, dual-mode relational persistence (PostgreSQL / SQLite WAL), edge collector agents, rule-based threat correlation (MITRE ATT&CK), and stateful SOC incident orchestration into a unified cyber defense cockpit.

---

## 🌐 Live Interactive SOC Console & Cloud Hosting

Experience the real-time Cyber SOC Console directly in your browser:  
👉 **[Open Live NetSentinel SOC Dashboard (GitHub Pages)](https://mohammed-aichour.github.io/NetSentinel-Enterprise/)**

* **Target Cloud Hosting:** [Vercel](https://vercel.com/) Serverless Functions (`api/index.py`) + Managed PostgreSQL ([Neon](https://neon.tech/) / [Supabase](https://supabase.com/) / Vercel Postgres).
* **Dual-Mode Persistence:** Automatically switches between cloud PostgreSQL (when `DATABASE_URL` is set) and zero-dependency SQLite with Write-Ahead Logging (`WAL`) mode when running locally.
* **Hybrid Monitoring Architecture:** Includes a standalone Python Collector Agent (`agent/collector_agent.py`) capable of running on private LANs to probe internal hardware (real ICMP ping + TCP service handshakes) and stream verified telemetry to the cloud backend.

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

### 1. Dual-Mode Relational Persistence Layer
* **PostgreSQL Engine:** Uses pure-Python `pg8000` driver (ideal for AWS Lambda and Vercel Serverless) with SSL/TLS support and pyformat parameterized queries.
* **SQLite WAL Engine:** Fallback mode with zero configuration for local development, Docker containers, and test suites.
* **Automated Migration & Schema Init:** Automatically generates tables, constraints, foreign keys, and time-series indexes on startup.
* **Readiness Probes:** `/api/v1/ready` endpoint tests active database connectivity and returns device and alert statistics.

### 2. Standalone Edge Collector Agent (`agent/collector_agent.py`)
* Solves cloud serverless limitations by executing genuine network probes inside your local private network.
* Probes internal devices using real OS ICMP ping and TCP socket 3-way handshakes.
* Collects local host metrics (CPU, RAM utilization).
* Streams authenticated batch telemetry reports to `POST /api/v1/telemetry/report`.

### 3. Complete Device Inventory Management (CRUD)
* **Create:** Register new network devices with validation (IP address syntax, MAC, tier, role, services).
* **Read:** Search and filter by Tier (`EDGE`, `CORE`, `DMZ`, `SERVICES`, `DATABASE`, `ACCESS`), Health Status, or text search.
* **Update:** Modify metadata, hardware vendor, and exposed TCP services with audit logging.
* **Delete:** Remove decommissioned devices with automatic cascading deletions across topology links, telemetry, and alerts.

### 4. SIEM Threat Correlation & MITRE ATT&CK Mapping
The correlation engine runs window-based behavioral analysis to detect multi-stage cyber attacks:

| Rule ID | Name | MITRE ATT&CK | Threshold / Trigger | Action |
| :--- | :--- | :--- | :--- | :--- |
| **`SEC-R001`** | **SSH Credential Brute-Force** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | > 5 failed auths in 60s | Alerts SOC & flags host |
| **`SEC-R002`** | **Horizontal Port Sweep** | [T1046](https://attack.mitre.org/techniques/T1046/) | > 10 unique ports in 30s | Escalates incident to HIGH |
| **`SEC-R003`** | **Volumetric DDoS / Traffic Anomaly** | [T1498.001](https://attack.mitre.org/techniques/T1498/001/) | > 800 Mbps or > 40,000 PPS | Critical alert & auto-quarantine |
| **`SEC-R004`** | **Unauthorized Rogue MAC** | [T1200](https://attack.mitre.org/techniques/T1200/) | Unrecognized MAC on sensitive VLAN | Critical alert & switchport isolation |
| **`SEC-R005`** | **Core Link Flapping & Loss Burst** | `NMS-NET-01` | >= 4 state flaps in 60s or Loss > 10% | Stability warning & status degradation |

### 5. Cyber SOC Console & Attack Simulator
* **Interactive Canvas Topology:** Node-link network map with dynamic traffic pulses, tier column alignments, hover tooltips, and click-to-inspect drawers.
* **Real-Time Streaming Charts:** Smooth SVG/Canvas area charts tracking aggregate throughput, average latency, and interface drops.
* **Attack Simulator:** 1-click execution of 5 realistic cyber scenarios: DDoS surges, SSH brute-force, horizontal port sweep, backbone link flapping, and rogue MAC injection.
* **Live Network Probe Panel:** Execute real OS ICMP Echo probes and TCP 3-way handshakes against target hosts directly from the SOC console.
* **Host Quarantine & Compliance Audit Trail:** 1-click software isolation with full audit compliance logging (`audit_log`).
* **Closed-Loop Health Auto-Recovery:** Automatically restores degraded device status (`ONLINE`) upon incident resolution.

---

## 📚 Complete Project Documentation

Comprehensive guides are available in the [`docs/`](docs/) directory:

- 📖 **[Guide Pédagogique & Architectural (Français)](docs/PROJECT_GUIDE.md)** — Explications approfondies de l'architecture, du fonctionnement du SIEM, de la boucle de remédiation, et de l'honnêteté technique.
- ⚙️ **[Guide d'Installation & Démarrage](docs/INSTALLATION.md)** — Instructions pas à pas pour Windows, Linux, Vercel et Docker.
- 🧪 **[Guide de Validation & Tests Automatisés](docs/TESTING.md)** — Détail des 39 tests automatisés et de la validation de bout en bout.
- 📡 **[Catalogue de l'API REST v1](docs/API.md)** — Spécification complète des requêtes et réponses JSON pour tous les endpoints.
- 🛡️ **[Référentiel des Règles de Détection SIEM](docs/DETECTION_RULES.md)** — Analyse détaillée des règles SEC-R001 à SEC-R005 et mappage MITRE ATT&CK.

---

## 🚀 Quickstart & Installation

### Prerequisites
* Python 3.10+ (tested on Python 3.11, 3.12, 3.13)
* Node.js (for Vercel CLI / frontend verification)
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
python run.py
```
Open your browser at **`http://localhost:8080/`** to access the SOC Console.

### Method 2: Running the Standalone Collector Agent (Local Network)
```bash
# In a separate terminal on your LAN or workstation:
python agent/collector_agent.py --server-url http://localhost:8080/api/v1 --interval 10
```

### Method 3: Vercel Cloud Serverless Deployment
```bash
# 1. Login to Vercel
npx vercel login

# 2. Deploy preview or production
npx vercel --prod

# 3. Set your PostgreSQL database connection string in Vercel Environment Variables:
# DATABASE_URL=postgresql://user:password@host:port/dbname?sslmode=require
```

### Method 4: Docker / Docker Compose
```bash
# Build and run containerized platform
docker-compose up -d

# Check running status and health probe
docker ps
```

---

## 🧪 Automated Test Suite

The test suite thoroughly verifies network probes, telemetry collectors, threat correlation heuristics, alert state transitions, database persistence, device CRUD, and REST API endpoints:

```bash
# Run pytest with verbose test discovery
pytest -v
```

### Verified Test Matrix (39/39 Passing — 100%):
```text
tests/test_alert_manager.py::TestAlertManager::test_alert_acknowledgment_and_resolution PASSED [  2%]
tests/test_alert_manager.py::TestAlertManager::test_alert_processing_and_deduplication PASSED [  5%]
tests/test_api.py::TestRestAPI::test_all_simulation_scenarios PASSED     [  7%]
tests/test_api.py::TestRestAPI::test_audit_logs_endpoint PASSED          [ 10%]
tests/test_api.py::TestRestAPI::test_closed_loop_lifecycle PASSED        [ 12%]
tests/test_api.py::TestRestAPI::test_device_detail_endpoint PASSED       [ 15%]
tests/test_api.py::TestRestAPI::test_device_probe_endpoint PASSED        [ 17%]
tests/test_api.py::TestRestAPI::test_device_quarantine_toggle PASSED     [ 20%]
tests/test_api.py::TestRestAPI::test_devices_listing_and_filtering PASSED [ 23%]
tests/test_api.py::TestRestAPI::test_events_ingest_and_retrieval PASSED  [ 25%]
tests/test_api.py::TestRestAPI::test_health_endpoint PASSED              [ 28%]
tests/test_api.py::TestRestAPI::test_simulation_attack_endpoint PASSED   [ 30%]
tests/test_api.py::TestRestAPI::test_telemetry_live_endpoint PASSED      [ 33%]
tests/test_api.py::TestRestAPI::test_topology_endpoint PASSED            [ 35%]
tests/test_collector.py::TestNetworkCollector::test_local_telemetry_metrics PASSED [ 38%]
tests/test_collector.py::TestNetworkCollector::test_localhost_ping PASSED [ 41%]
tests/test_collector.py::TestNetworkCollector::test_quarantined_device_telemetry PASSED [ 43%]
tests/test_collector.py::TestNetworkCollector::test_synthetic_device_telemetry_firewall PASSED [ 46%]
tests/test_collector.py::TestNetworkCollector::test_tcp_port_probe_refused PASSED [ 48%]
tests/test_collector.py::TestNetworkCollector::test_unreachable_ping PASSED [ 51%]
tests/test_correlator.py::TestEventCorrelator::test_interface_flapping_detection PASSED [ 53%]
tests/test_correlator.py::TestEventCorrelator::test_port_scan_detection PASSED [ 56%]
tests/test_correlator.py::TestEventCorrelator::test_rogue_mac_detection PASSED [ 58%]
tests/test_correlator.py::TestEventCorrelator::test_ssh_brute_force_detection PASSED [ 61%]
tests/test_correlator.py::TestEventCorrelator::test_telemetry_threshold_alerts PASSED [ 64%]
tests/test_correlator.py::TestEventCorrelator::test_volumetric_ddos_detection PASSED [ 66%]
tests/test_database_persistence.py::TestDatabasePersistence::test_agent_telemetry_batch_ingestion PASSED [ 69%]
tests/test_database_persistence.py::TestDatabasePersistence::test_device_crud_lifecycle PASSED [ 71%]
tests/test_database_persistence.py::TestDatabasePersistence::test_postgres_url_parser PASSED [ 74%]
tests/test_database_persistence.py::TestDatabasePersistence::test_query_translation_for_postgres PASSED [ 76%]
tests/test_database_persistence.py::TestDatabasePersistence::test_row_dict_semantics PASSED [ 79%]
tests/test_database_persistence.py::TestDatabasePersistence::test_sqlite_wal_mode_and_readiness PASSED [ 82%]
tests/test_device_crud_and_agent.py::TestDeviceCrudAndAgentApi::test_agent_telemetry_report_endpoint PASSED [ 84%]
tests/test_device_crud_and_agent.py::TestDeviceCrudAndAgentApi::test_cors_headers_and_preflight PASSED [ 87%]
tests/test_device_crud_and_agent.py::TestDeviceCrudAndAgentApi::test_device_crud_rest_lifecycle PASSED [ 89%]
tests/test_device_crud_and_agent.py::TestDeviceCrudAndAgentApi::test_ready_endpoint PASSED [ 92%]
tests/test_frontend_assets.py::TestFrontendAssets::test_dom_elements_present_in_html PASSED [ 94%]
tests/test_frontend_assets.py::TestFrontendAssets::test_headless_node_dom_initialization_regression PASSED [ 97%]
tests/test_frontend_assets.py::TestFrontendAssets::test_javascript_syntax_validity PASSED [100%]

============================= 39 passed in 9.66s ==============================
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | System operational status, monitored node count, and health summary. |
| `GET` | `/api/v1/ready` | Readiness probe verifying active database connection and registered nodes. |
| `GET` | `/api/v1/topology` | Returns network nodes and graph links organized by tier. |
| `GET` | `/api/v1/devices` | Returns inventory catalog with optional `tier`, `status`, and `q` search. |
| `POST` | `/api/v1/devices` | Creates a new monitored device with input validation and audit logging. |
| `GET` | `/api/v1/devices/<id>` | Full metadata, open services, and historical telemetry for a device. |
| `PUT` | `/api/v1/devices/<id>` | Updates device metadata, IP address, tier, or services. |
| `DELETE` | `/api/v1/devices/<id>` | Removes device and cascades deletions across links, telemetry, and alerts. |
| `POST` | `/api/v1/devices/<id>/probe` | Executes live ICMP ping and service TCP port checks. |
| `POST` | `/api/v1/devices/<id>/quarantine` | Enforces or releases host network isolation with compliance audit. |
| `GET` | `/api/v1/telemetry/live` | Real-time aggregate cluster telemetry with automatic historical pruning. |
| `POST` | `/api/v1/telemetry/report` | Ingests batch telemetry reports from standalone local collector agent. |
| `GET` | `/api/v1/alerts` | Active alerts with `status` and `severity` filters. |
| `POST` | `/api/v1/alerts/<id>/acknowledge` | SOC operator acknowledgment of an alert. |
| `POST` | `/api/v1/alerts/<id>/resolve` | Resolves alert with note; triggers closed-loop node health recovery. |
| `POST` | `/api/v1/events/ingest` | Ingests SIEM security events (single or batch) into correlation pipeline. |
| `GET` | `/api/v1/events` | Retrieves raw SIEM ingested threat event stream. |
| `GET` | `/api/v1/audit` | Retrieves operator action audit log for compliance. |
| `POST` | `/api/v1/simulation/attack` | Injects attack scenarios (`ddos`, `brute_force`, `port_scan`, `link_flap`, `rogue_mac`). |

---

## 📁 Repository Structure

```
NetSentinel-Enterprise/
├── agent/
│   └── collector_agent.py     # Standalone local LAN collector & probe streamer
├── api/
│   └── index.py               # Vercel Serverless Function WSGI entrypoint
├── backend/
│   ├── app.py                 # Application factory & CORS configuration
│   ├── config.py              # Environment settings, thresholds & MITRE rules
│   ├── database.py            # Dual-mode PostgreSQL & SQLite WAL persistence
│   ├── engine/
│   │   ├── collector.py       # Live ICMP/TCP probe & synthetic telemetry
│   │   ├── correlator.py      # SIEM threat correlator (Rules SEC-R001 to R005)
│   │   ├── alert_manager.py   # State machine, closed-loop health & deduplication
│   │   └── simulator.py       # Topology seeder & 5 cyber attack scenarios
│   ├── models/
│   │   └── schemas.py         # Domain dataclasses & serialization
│   └── routes/
│       └── api.py             # REST API Blueprint (/api/v1/...)
├── frontend/                  # Production SOC Web Application
│   ├── index.html             # Cyber SOC console layout & diagnostic modals
│   ├── css/soc.css            # Dark glassmorphism SOC theme
│   └── js/
│       ├── app.js             # State controller, Device CRUD & API sync
│       ├── topology.js        # Interactive Canvas topology engine
│       └── charts.js          # Real-time streaming area charts
├── docs/                      # GitHub Pages deployment & documentation
│   ├── PROJECT_GUIDE.md       # Comprehensive French mentoring & architecture guide
│   ├── INSTALLATION.md        # Step-by-step setup guide for Windows/Linux/Vercel
│   ├── TESTING.md             # Automated test suite breakdown & execution guide
│   ├── API.md                 # Complete REST API reference
│   ├── DETECTION_RULES.md     # In-depth MITRE ATT&CK rule specification
│   ├── index.html             # Live interactive demo
│   └── ...
├── tests/                     # Automated test suite (39 passing tests — 100%)
│   ├── test_collector.py
│   ├── test_correlator.py
│   ├── test_alert_manager.py
│   ├── test_api.py
│   ├── test_database_persistence.py
│   ├── test_device_crud_and_agent.py
│   └── test_frontend_assets.py
├── vercel.json                # Vercel Serverless routing & rewrites
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── run.py                     # Primary entry point
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
