"""
NetSentinel Enterprise - REST API Controller (/api/v1/...)
Full enterprise endpoint catalog for Device Inventory CRUD, Telemetry Streams, Alerts, and SOC Operations.
Author: Mohammed Aichour
"""

from flask import Blueprint, jsonify, request
from typing import Dict, Any
from datetime import datetime, timezone

from backend.config import VERSION, ENTERPRISE_NAME, SOC_NAME, API_KEY
from backend.database import (
    get_connection,
    check_database_readiness,
    DeviceRepository,
    AlertRepository,
    TelemetryRepository,
    SecurityEventRepository,
    AuditLogRepository
)
from backend.engine.collector import NetworkProbe, TelemetryCollector
from backend.engine.correlator import EventCorrelator
from backend.engine.alert_manager import AlertManager
from backend.engine.simulator import CyberAttackSimulator

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")

# Global engine singletons for the API session
correlator = EventCorrelator()
alert_manager = AlertManager()
attack_simulator = CyberAttackSimulator(correlator, alert_manager)


@api_bp.before_request
def authenticate_request():
    """Optional API Key authentication middleware for mutating requests."""
    if not API_KEY:
        return None

    # Allow read-only monitoring and health/readiness probes without API key
    if request.method in ("GET", "OPTIONS") or request.path.endswith("/health") or request.path.endswith("/ready"):
        return None

    client_key = request.headers.get("X-API-Key")
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        client_key = auth_header[7:].strip()

    if client_key != API_KEY:
        return jsonify({
            "error": "Unauthorized. Provide valid X-API-Key or Bearer token.",
            "status": "UNAUTHORIZED"
        }), 401


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


@api_bp.route("/ready", methods=["GET"])
def get_readiness():
    """Readiness probe validating database persistence connectivity and catalog status."""
    db_status = check_database_readiness()
    if db_status["ready"]:
        return jsonify({
            "status": "READY",
            "database_engine": db_status["engine"],
            "devices_registered": db_status.get("device_count", 0),
            "active_alerts": db_status.get("active_alerts", 0),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200
    else:
        return jsonify({
            "status": "NOT_READY",
            "error": db_status.get("error", "Database connection failed"),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 503


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


@api_bp.route("/devices", methods=["POST"])
def create_device():
    """Creates a new device in the inventory."""
    payload = request.get_json(silent=True)
    if not payload or not isinstance(payload, dict):
        return jsonify({"error": "Valid JSON object body is required."}), 400

    operator = request.headers.get("X-SOC-Operator", payload.get("operator", "SOC-Operator"))
    try:
        created = DeviceRepository.create(payload, operator=operator)
        return jsonify({"status": "CREATED", "device": created}), 201
    except ValueError as e:
        err_msg = str(e)
        status_code = 409 if "already exists" in err_msg or "in use" in err_msg else 400
        return jsonify({"error": err_msg}), status_code


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


@api_bp.route("/devices/<device_id>", methods=["PUT"])
def update_device(device_id: str):
    """Updates an existing device's metadata."""
    payload = request.get_json(silent=True)
    if not payload or not isinstance(payload, dict):
        return jsonify({"error": "Valid JSON object body is required."}), 400

    operator = request.headers.get("X-SOC-Operator", payload.get("operator", "SOC-Operator"))
    try:
        updated = DeviceRepository.update(device_id, payload, operator=operator)
        if not updated:
            return jsonify({"error": f"Device '{device_id}' not found"}), 404
        return jsonify({"status": "UPDATED", "device": updated}), 200
    except ValueError as e:
        err_msg = str(e)
        status_code = 409 if "in use" in err_msg or "already exists" in err_msg else 400
        return jsonify({"error": err_msg}), status_code


@api_bp.route("/devices/<device_id>", methods=["DELETE"])
def delete_device(device_id: str):
    """Deletes a device from inventory and cascades deletions across links and telemetry."""
    operator = request.headers.get("X-SOC-Operator", "SOC-Operator")
    success = DeviceRepository.delete(device_id, operator=operator)
    if not success:
        return jsonify({"error": f"Device '{device_id}' not found"}), 404
    return jsonify({"status": "DELETED", "message": f"Device '{device_id}' deleted successfully."}), 200


@api_bp.route("/devices/<device_id>/probe", methods=["POST"])
def probe_device(device_id: str):
    """Executes live ICMP ping and service TCP port checks against the device."""
    device = DeviceRepository.get_by_id(device_id)
    if not device:
        return jsonify({"error": f"Device '{device_id}' not found"}), 404

    ping_res = NetworkProbe.ping_host(device["ip_address"])
    is_reachable = ping_res["reachable"]
    rtt_ms = ping_res["rtt_ms"]
    loss_pct = ping_res["packet_loss_percent"]

    port_results = []
    for svc in device.get("services", []):
        port = svc.get("port")
        if port:
            port_res = NetworkProbe.check_tcp_port(device["ip_address"], port)
            port_results.append({
                "port": port,
                "name": svc.get("name", "Unknown"),
                "status": port_res["status"],
                "is_open": port_res["is_open"],
                "rtt_ms": port_res["rtt_ms"],
                "diagnosis": port_res["diagnosis"]
            })

    # Save a telemetry sample based on probe results (marked as real probe)
    sample = {
        "device_id": device_id,
        "is_simulated": False,
        "collector_method": "REAL_ICMP_TCP_PROBE",
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
        "hostname": device["hostname"],
        "ip_address": device["ip_address"],
        "icmp": ping_res,
        "services": port_results,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@api_bp.route("/devices/<device_id>/quarantine", methods=["POST"])
def toggle_quarantine(device_id: str):
    """
    Enforces or releases network quarantine / port isolation on a host.
    Operates at the software NMS routing level and logs to compliance audit trail.
    """
    device = DeviceRepository.get_by_id(device_id)
    if not device:
        return jsonify({"error": f"Device '{device_id}' not found"}), 404

    req_json = request.get_json(silent=True) or {}
    quarantine_state = req_json.get("quarantine", not device["is_quarantined"])
    operator = req_json.get("operator", "SOC-Operator")
    reason = req_json.get("reason", "Administrative software isolation via NetSentinel Console")

    DeviceRepository.set_quarantine(device_id, quarantine_state, operator=operator, reason=reason)
    action_text = "quarantined" if quarantine_state else "released from quarantine"
    
    return jsonify({
        "status": "ACCEPTED",
        "isolation_type": "SOFTWARE_NMS_ROUTING_FILTER",
        "message": f"Device '{device_id}' has been {action_text} by {operator}.",
        "device_id": device_id,
        "is_quarantined": quarantine_state,
        "audit_note": "Host traffic simulated as dropped (100% loss) in telemetry collector."
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

    # Prune historical samples beyond retention limit to prevent database growth
    TelemetryRepository.prune_old_samples(keep_per_device=120)

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


@api_bp.route("/telemetry/report", methods=["POST"])
def ingest_telemetry_report():
    """Ingests batch telemetry collected by a standalone local collector agent."""
    payload = request.get_json(silent=True)
    if not payload or not isinstance(payload, dict):
        return jsonify({"error": "Valid JSON report body is required."}), 400
    if "probes" not in payload or not isinstance(payload["probes"], list):
        return jsonify({"error": "Report must contain a 'probes' array."}), 400

    result = TelemetryRepository.insert_agent_report(payload)
    return jsonify(result), 200


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


@api_bp.route("/events/ingest", methods=["POST"])
def ingest_event():
    """
    Ingests raw security events into the SIEM pipeline.
    Supports single event object or array of event objects.
    Evaluates correlation rules and triggers stateful alerts.
    """
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "JSON body is required."}), 400

    items = payload if isinstance(payload, list) else [payload]
    if not items:
        return jsonify({"error": "No events provided."}), 400

    triggered_alerts = []
    ingested_count = 0

    for data in items:
        source_ip = data.get("source_ip")
        target_id = data.get("target_device_id") or data.get("device_id")
        event_type = data.get("event_type", "GENERIC_EVENT").upper()

        if not source_ip or not target_id:
            continue

        normalized = dict(data)
        normalized["target_device_id"] = target_id
        SecurityEventRepository.insert(normalized)
        ingested_count += 1

        if event_type == "AUTH_FAILURE":
            correlator.record_auth_event(source_ip, target_id, success=False, protocol=data.get("protocol", "SSH"))
            for a in correlator.check_brute_force():
                al = alert_manager.process_incoming_alert(a)
                if al:
                    triggered_alerts.append(al)

        elif event_type == "PORT_ATTEMPT":
            port = int(data.get("port", 0))
            if port > 0:
                correlator.record_port_attempt(source_ip, target_id, port=port)
                for a in correlator.check_port_scan():
                    al = alert_manager.process_incoming_alert(a)
                    if al:
                        triggered_alerts.append(al)

        elif event_type == "MAC_OBSERVED":
            mac = data.get("mac_address", "")
            vlan = data.get("vlan", "VLAN-10-CORE")
            alert = correlator.check_rogue_mac(target_id, mac, vlan=vlan)
            if alert:
                al = alert_manager.process_incoming_alert(alert)
                if al:
                    triggered_alerts.append(al)

        elif event_type == "LINK_TRANSITION":
            iface = data.get("interface", "eth0")
            state = data.get("state", "DOWN")
            correlator.record_link_transition(target_id, iface, state)
            for a in correlator.check_interface_flapping():
                al = alert_manager.process_incoming_alert(a)
                if al:
                    triggered_alerts.append(al)

    if ingested_count == 0:
        return jsonify({"error": "No valid events ingested. Fields 'source_ip' and 'target_device_id' (or 'device_id') are required."}), 400

    return jsonify({
        "status": "INGESTED",
        "ingested_count": ingested_count,
        "alerts_triggered_count": len(triggered_alerts),
        "alerts": triggered_alerts
    }), 201


@api_bp.route("/events", methods=["GET"])
def list_events():
    """Returns raw SIEM ingested security event stream."""
    limit = int(request.args.get("limit", 50))
    events = SecurityEventRepository.list_events(limit=limit)
    return jsonify({"count": len(events), "events": events})


@api_bp.route("/audit", methods=["GET"])
def list_audit_logs():
    """Returns compliance audit logs of all operator actions."""
    limit = int(request.args.get("limit", 50))
    logs = AuditLogRepository.list_logs(limit=limit)
    return jsonify({"count": len(logs), "logs": logs})


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
    elif attack_type in ("rogue_mac", "rogue"):
        alert = correlator.check_rogue_mac(target_id, mac_address="DE:AD:BE:EF:00:99", vlan="VLAN-30-DATABASE")
        if alert:
            alert_manager.process_incoming_alert(alert)
        res = {"scenario": "ROGUE_MAC", "target": target_id, "alert_triggered": bool(alert)}
    else:
        return jsonify({"error": f"Unknown attack type '{attack_type}'. Choose: ddos, brute_force, port_scan, link_flap, rogue_mac."}), 400

    return jsonify({"status": "SUCCESS", "result": res})
