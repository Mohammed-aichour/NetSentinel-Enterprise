"""
NetSentinel Enterprise - REST API Controller (/api/v1/...)
Full enterprise endpoint catalog for Device Inventory, Telemetry Streams, Alerts, and SOC Operations.
"""

from flask import Blueprint, jsonify, request
from typing import Dict, Any
from datetime import datetime, timezone

from backend.config import VERSION, ENTERPRISE_NAME, SOC_NAME
from backend.database import get_connection, DeviceRepository, AlertRepository, TelemetryRepository
from backend.engine.collector import NetworkProbe, TelemetryCollector
from backend.engine.correlator import EventCorrelator
from backend.engine.alert_manager import AlertManager
from backend.engine.simulator import CyberAttackSimulator

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")

# Global engine singletons for the API session
correlator = EventCorrelator()
alert_manager = AlertManager()
attack_simulator = CyberAttackSimulator(correlator, alert_manager)


@api_bp.route("/health", methods=["GET"])
def get_health():
    """System health check and operational meta."""
    devices = DeviceRepository.list_all()
    active_alerts = AlertRepository.list_alerts(status_filter="NEW")
    
    online_count = sum(1 for d in devices if d["status"] == "ONLINE")
    critical_count = sum(1 for d in devices if d["status"] == "CRITICAL")
    degraded_count = sum(1 for d in devices if d["status"] == "DEGRADED")

    return jsonify({
        "status": "HEALTHY",
        "version": VERSION,
        "enterprise": ENTERPRISE_NAME,
        "soc": SOC_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "total_devices": len(devices),
            "online": online_count,
            "degraded": degraded_count,
            "critical": critical_count,
            "unresolved_alerts": len(active_alerts)
        }
    })


@api_bp.route("/topology", methods=["GET"])
def get_topology():
    """Returns network graph nodes and interconnect links for SOC visualization."""
    devices = DeviceRepository.list_all()
    
    with get_connection() as conn:
        link_rows = conn.execute("SELECT * FROM topology_links").fetchall()
        links = [dict(r) for r in link_rows]

    # Structure nodes with UI tier layout guidance
    nodes = []
    tier_ranks = {
        "EDGE": 0,
        "CORE": 1,
        "DMZ": 2,
        "SERVICES": 3,
        "DATABASE": 4,
        "ACCESS": 5
    }

    for d in devices:
        nodes.append({
            "id": d["id"],
            "hostname": d["hostname"],
            "ip": d["ip_address"],
            "tier": d["tier"],
            "rank": tier_ranks.get(d["tier"], 3),
            "role": d["role"],
            "vendor": d["vendor"],
            "status": d["status"],
            "is_quarantined": d["is_quarantined"],
            "services_count": len(d.get("services", []))
        })

    return jsonify({
        "nodes": nodes,
        "links": links,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@api_bp.route("/devices", methods=["GET"])
def list_devices():
    """Lists registered devices with optional tier, status, and search filters."""
    tier = request.args.get("tier")
    status = request.args.get("status")
    search = request.args.get("q", "").lower()

    devices = DeviceRepository.list_all()

    if tier:
        devices = [d for d in devices if d["tier"].upper() == tier.upper()]
    if status:
        devices = [d for d in devices if d["status"].upper() == status.upper()]
    if search:
        devices = [
            d for d in devices
            if search in d["hostname"].lower() or search in d["ip_address"] or search in d["role"].lower()
        ]

    return jsonify({"count": len(devices), "devices": devices})


@api_bp.route("/devices/<device_id>", methods=["GET"])
def get_device(device_id: str):
    """Retrieves specific device metadata and recent telemetry."""
    device = DeviceRepository.get_by_id(device_id)
    if not device:
        return jsonify({"error": f"Device '{device_id}' not found"}), 404

    history = TelemetryRepository.get_device_history(device_id, limit=30)
    return jsonify({
        "device": device,
        "telemetry_history": history
    })


@api_bp.route("/devices/<device_id>/probe", methods=["POST"])
def probe_device(device_id: str):
    """Executes live ICMP ping and service TCP port checks against the device."""
    device = DeviceRepository.get_by_id(device_id)
    if not device:
        return jsonify({"error": f"Device '{device_id}' not found"}), 404

    is_reachable, rtt_ms, loss_pct = NetworkProbe.ping_host(device["ip_address"])

    port_results = []
    for svc in device.get("services", []):
        port = svc.get("port")
        if port:
            is_open, resp_ms = NetworkProbe.check_tcp_port(device["ip_address"], port)
            port_results.append({
                "port": port,
                "name": svc.get("name", "Unknown"),
                "status": "OPEN" if is_open else "CLOSED",
                "rtt_ms": resp_ms
            })

    # Save a telemetry sample based on probe results
    sample = {
        "device_id": device_id,
        "cpu_percent": 35.0,
        "memory_percent": 50.0,
        "latency_ms": rtt_ms,
        "packet_loss_percent": loss_pct,
        "bandwidth_in_mbps": 50.0 if is_reachable else 0.0,
        "bandwidth_out_mbps": 40.0 if is_reachable else 0.0,
        "packets_per_sec": 1200 if is_reachable else 0
    }
    TelemetryRepository.insert_sample(sample)

    return jsonify({
        "device_id": device_id,
        "ip_address": device["ip_address"],
        "icmp": {
            "reachable": is_reachable,
            "rtt_ms": rtt_ms,
            "packet_loss_percent": loss_pct
        },
        "services": port_results,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@api_bp.route("/devices/<device_id>/quarantine", methods=["POST"])
def toggle_quarantine(device_id: str):
    """Enforces or releases network quarantine / port isolation on a host."""
    device = DeviceRepository.get_by_id(device_id)
    if not device:
        return jsonify({"error": f"Device '{device_id}' not found"}), 404

    req_json = request.get_json(silent=True) or {}
    quarantine_state = req_json.get("quarantine", not device["is_quarantined"])

    DeviceRepository.set_quarantine(device_id, quarantine_state)
    action_text = "quarantined" if quarantine_state else "released from quarantine"
    
    return jsonify({
        "message": f"Device '{device_id}' has been {action_text}.",
        "device_id": device_id,
        "is_quarantined": quarantine_state
    })


@api_bp.route("/telemetry/live", methods=["GET"])
def get_live_telemetry():
    """Returns real-time cluster telemetry snapshot across all monitored nodes."""
    devices = DeviceRepository.list_all()
    samples = []
    
    total_bw_in = 0.0
    total_bw_out = 0.0
    total_pps = 0
    total_latency = 0.0

    for dev in devices:
        s = TelemetryCollector.sample_device_telemetry(dev)
        TelemetryRepository.insert_sample(s)
        samples.append(s)

        total_bw_in += s["bandwidth_in_mbps"]
        total_bw_out += s["bandwidth_out_mbps"]
        total_pps += s["packets_per_sec"]
        total_latency += s["latency_ms"]

    avg_lat = round(total_latency / len(devices), 2) if devices else 0.0

    return jsonify({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cluster_summary": {
            "monitored_nodes": len(devices),
            "aggregate_bandwidth_in_mbps": round(total_bw_in, 2),
            "aggregate_bandwidth_out_mbps": round(total_bw_out, 2),
            "aggregate_pps": total_pps,
            "cluster_avg_latency_ms": avg_lat
        },
        "samples": samples
    })


@api_bp.route("/alerts", methods=["GET"])
def list_alerts():
    """Lists alerts with status and limit filters."""
    status_filter = request.args.get("status")
    limit = int(request.args.get("limit", 50))
    alerts = AlertRepository.list_alerts(status_filter=status_filter, limit=limit)
    return jsonify({"count": len(alerts), "alerts": alerts})


@api_bp.route("/alerts/<alert_id>/acknowledge", methods=["POST"])
def acknowledge_alert(alert_id: str):
    """SOC Analyst acknowledgment of an alert."""
    req_json = request.get_json(silent=True) or {}
    operator = req_json.get("operator", "SOC-Analyst-Mohammed")
    success = alert_manager.acknowledge_alert(alert_id, operator=operator)
    if not success:
        return jsonify({"error": f"Alert '{alert_id}' not found or already acknowledged"}), 404
    return jsonify({"message": f"Alert '{alert_id}' successfully acknowledged by {operator}."})


@api_bp.route("/alerts/<alert_id>/resolve", methods=["POST"])
def resolve_alert(alert_id: str):
    """Resolves an alert and resets device health."""
    req_json = request.get_json(silent=True) or {}
    note = req_json.get("note", "Remediated via SOC firewall rule")
    success = alert_manager.resolve_alert(alert_id, resolution_note=note)
    if not success:
        return jsonify({"error": f"Alert '{alert_id}' not found"}), 404
    return jsonify({"message": f"Alert '{alert_id}' resolved."})


@api_bp.route("/simulation/attack", methods=["POST"])
def simulate_attack():
    """Triggers realistic simulated cyber attacks to test detection & alerting."""
    req = request.get_json(silent=True) or {}
    attack_type = req.get("attack_type", "ddos").lower()
    target_id = req.get("target_id", "fw-edge-01")

    if attack_type == "ddos":
        res = attack_simulator.trigger_ddos_spike(target_id=target_id)
    elif attack_type in ("brute_force", "ssh"):
        res = attack_simulator.trigger_ssh_brute_force(target_id=target_id)
    elif attack_type in ("port_scan", "scan"):
        res = attack_simulator.trigger_port_scan(target_id=target_id)
    elif attack_type in ("link_flap", "flap"):
        res = attack_simulator.trigger_link_flap(device_id=target_id)
    else:
        return jsonify({"error": f"Unknown attack type '{attack_type}'. Choose: ddos, brute_force, port_scan, link_flap."}), 400

    return jsonify({"status": "SUCCESS", "result": res})
