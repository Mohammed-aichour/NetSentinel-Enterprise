"""
NetSentinel Enterprise - Stateful Alert Manager & Incident Lifecycle Engine
Handles alert de-duplication, state transitions, threshold hysteresis, and notification dispatch.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from backend.database import AlertRepository, DeviceRepository

logger = logging.getLogger("netsentinel.alert_manager")


class AlertManager:
    """
    Orchestrates the lifecycle of active alerts and incidents:
    ingestion -> de-duplication -> escalation -> acknowledgment -> remediation.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        self._active_signatures: Dict[str, str] = {}  # (device_id, rule_id) -> alert_id

    def process_incoming_alert(self, alert: Dict[str, Any], auto_quarantine: bool = False) -> Optional[Dict[str, Any]]:
        """
        Processes an alert through de-duplication filter.
        Prevents alert fatigue by ignoring duplicate alerts for already open conditions.
        """
        sig = f"{alert['device_id']}:{alert.get('rule_id', alert['title'])}"
        
        # Check if an alert with this signature is currently active (NEW or ACKNOWLEDGED)
        existing_alerts = AlertRepository.list_alerts(status_filter="NEW", limit=100, db_path=self.db_path)
        existing_ack = AlertRepository.list_alerts(status_filter="ACKNOWLEDGED", limit=100, db_path=self.db_path)
        active_list = existing_alerts + existing_ack

        for existing in active_list:
            existing_sig = f"{existing['device_id']}:{existing.get('rule_id', existing['title'])}"
            if existing_sig == sig:
                # Already active, do not create duplicate
                return None

        # Insert new alert
        AlertRepository.insert(alert, db_path=self.db_path)
        logger.warning(f"NEW ALERT TRIGGERED [{alert['severity']}]: {alert['title']} on {alert['device_id']}")

        # Device status degradation
        if alert["severity"] == "CRITICAL":
            DeviceRepository.set_status(alert["device_id"], "CRITICAL", db_path=self.db_path)
            if auto_quarantine:
                DeviceRepository.set_quarantine(alert["device_id"], True, db_path=self.db_path)
                logger.info(f"Auto-quarantined device {alert['device_id']} due to critical threat.")
        elif alert["severity"] == "HIGH":
            DeviceRepository.set_status(alert["device_id"], "DEGRADED", db_path=self.db_path)

        return alert

    def acknowledge_alert(self, alert_id: str, operator: str = "SOC-Lead") -> bool:
        """Marks alert as acknowledged by a human analyst."""
        return AlertRepository.acknowledge(alert_id, operator=operator, db_path=self.db_path)

    def resolve_alert(self, alert_id: str, resolution_note: str = "Threat mitigated", db_path: Optional[str] = None) -> bool:
        """Resolves alert and restores device health if no other critical alerts remain."""
        target_db = db_path or self.db_path
        alert = AlertRepository.get_by_id(alert_id, db_path=target_db)
        success = AlertRepository.resolve(alert_id, note=resolution_note, db_path=target_db)
        if success:
            logger.info(f"Alert {alert_id} marked as RESOLVED. Note: {resolution_note}")
            if alert and "device_id" in alert:
                new_status = DeviceRepository.recompute_status(alert["device_id"], db_path=target_db)
                logger.info(f"Device {alert['device_id']} health dynamically recomputed to: {new_status}")
        return success
