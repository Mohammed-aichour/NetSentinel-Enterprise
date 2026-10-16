"""
NetSentinel Enterprise - SQLite Database Layer & Schema Management
High-performance relational persistence with WAL mode & automated schema migration.
"""

import sqlite3
import json
import logging
import contextlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from backend.config import DB_PATH

logger = logging.getLogger("netsentinel.database")


def open_raw_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Creates a configured SQLite connection with row factories and WAL mode."""
    target_path = db_path or DB_PATH
    Path(target_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


@contextlib.contextmanager
def get_connection(db_path: Optional[str] = None):
    """Context manager that auto-commits and explicitly closes SQLite connections."""
    conn = open_raw_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None) -> None:
    """Initializes tables, indexes, and initial constraints."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        # 1. Devices Inventory
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                ip_address TEXT NOT NULL UNIQUE,
                mac_address TEXT NOT NULL,
                tier TEXT NOT NULL,
                role TEXT NOT NULL,
                vendor TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ONLINE',
                services TEXT NOT NULL DEFAULT '[]',
                is_quarantined INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)

        # 2. Topology Links
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS topology_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                link_type TEXT NOT NULL DEFAULT '10GbE-Trunk',
                bandwidth_mbps INTEGER NOT NULL DEFAULT 10000,
                status TEXT NOT NULL DEFAULT 'UP',
                FOREIGN KEY (source_id) REFERENCES devices(id) ON DELETE CASCADE,
                FOREIGN KEY (target_id) REFERENCES devices(id) ON DELETE CASCADE,
                UNIQUE(source_id, target_id)
            );
        """)

        # 3. Telemetry Samples (Time Series)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                cpu_percent REAL NOT NULL,
                memory_percent REAL NOT NULL,
                latency_ms REAL NOT NULL,
                packet_loss_percent REAL NOT NULL,
                bandwidth_in_mbps REAL NOT NULL,
                bandwidth_out_mbps REAL NOT NULL,
                packets_per_sec INTEGER NOT NULL,
                FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
            );
        """)

        # Indexes for fast time-series queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_telemetry_device_time
            ON telemetry_samples(device_id, timestamp DESC);
        """)

        # 4. Alerts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                rule_id TEXT,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'NEW',
                mitre_id TEXT,
                created_at TEXT NOT NULL,
                acknowledged_at TEXT,
                resolved_at TEXT,
                resolution_note TEXT,
                FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
            );
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_status_severity
            ON alerts(status, severity, created_at DESC);
        """)

        # 5. Security Threat Events (SIEM Stream)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                target_device_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_summary TEXT NOT NULL,
                severity TEXT NOT NULL,
                FOREIGN KEY (target_device_id) REFERENCES devices(id) ON DELETE CASCADE
            );
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_sec_events_time
            ON security_events(timestamp DESC);
        """)

        # 6. SOC Operator Audit Log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                operator TEXT NOT NULL,
                action TEXT NOT NULL,
                target_id TEXT NOT NULL,
                details TEXT
            );
        """)

        conn.commit()
    logger.info("Database schema initialized successfully.")


# Database Helper Operations
class DeviceRepository:
    @staticmethod
    def list_all(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        with get_connection(db_path) as conn:
            rows = conn.execute("""
                SELECT id, hostname, ip_address, mac_address, tier, role, vendor,
                       status, services, is_quarantined, last_seen, created_at
                FROM devices
                ORDER BY tier, hostname
            """).fetchall()
            devices = []
            for r in rows:
                item = dict(r)
                item["services"] = json.loads(item["services"]) if isinstance(item["services"], str) else item["services"]
                item["is_quarantined"] = bool(item["is_quarantined"])
                devices.append(item)
            return devices

    @staticmethod
    def get_by_id(device_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with get_connection(db_path) as conn:
            row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
            if not row:
                return None
            item = dict(row)
            item["services"] = json.loads(item["services"]) if isinstance(item["services"], str) else item["services"]
            item["is_quarantined"] = bool(item["is_quarantined"])
            return item

    @staticmethod
    def upsert(device: Dict[str, Any], db_path: Optional[str] = None) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        services_json = json.dumps(device.get("services", []))
        with get_connection(db_path) as conn:
            conn.execute("""
                INSERT INTO devices (id, hostname, ip_address, mac_address, tier, role, vendor,
                                     status, services, is_quarantined, last_seen, created_at)
                VALUES (:id, :hostname, :ip_address, :mac_address, :tier, :role, :vendor,
                        :status, :services, :is_quarantined, :last_seen, :created_at)
                ON CONFLICT(id) DO UPDATE SET
                    hostname = excluded.hostname,
                    ip_address = excluded.ip_address,
                    mac_address = excluded.mac_address,
                    tier = excluded.tier,
                    role = excluded.role,
                    vendor = excluded.vendor,
                    status = excluded.status,
                    services = excluded.services,
                    is_quarantined = excluded.is_quarantined,
                    last_seen = excluded.last_seen;
            """, {
                "id": device["id"],
                "hostname": device["hostname"],
                "ip_address": device["ip_address"],
                "mac_address": device["mac_address"],
                "tier": device.get("tier", "ACCESS"),
                "role": device.get("role", "Host"),
                "vendor": device.get("vendor", "Generic"),
                "status": device.get("status", "ONLINE"),
                "services": services_json,
                "is_quarantined": 1 if device.get("is_quarantined") else 0,
                "last_seen": device.get("last_seen", now_iso),
                "created_at": device.get("created_at", now_iso)
            })
            conn.commit()

    @staticmethod
    def set_status(device_id: str, status: str, db_path: Optional[str] = None) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_connection(db_path) as conn:
            conn.execute("UPDATE devices SET status = ?, last_seen = ? WHERE id = ?", (status, now_iso, device_id))
            conn.commit()

    @staticmethod
    def set_quarantine(device_id: str, quarantined: bool, db_path: Optional[str] = None) -> None:
        val = 1 if quarantined else 0
        new_status = "CRITICAL" if quarantined else "ONLINE"
        with get_connection(db_path) as conn:
            conn.execute("UPDATE devices SET is_quarantined = ?, status = ? WHERE id = ?", (val, new_status, device_id))
            conn.commit()


class AlertRepository:
    @staticmethod
    def list_alerts(status_filter: Optional[str] = None, limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        with get_connection(db_path) as conn:
            if status_filter:
                rows = conn.execute("""
                    SELECT a.*, d.hostname, d.ip_address, d.role
                    FROM alerts a
                    JOIN devices d ON a.device_id = d.id
                    WHERE a.status = ?
                    ORDER BY 
                        CASE a.severity 
                            WHEN 'CRITICAL' THEN 1 
                            WHEN 'HIGH' THEN 2 
                            WHEN 'MEDIUM' THEN 3 
                            WHEN 'LOW' THEN 4 
                            ELSE 5 
                        END,
                        a.created_at DESC
                    LIMIT ?
                """, (status_filter, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT a.*, d.hostname, d.ip_address, d.role
                    FROM alerts a
                    JOIN devices d ON a.device_id = d.id
                    ORDER BY 
                        CASE a.severity 
                            WHEN 'CRITICAL' THEN 1 
                            WHEN 'HIGH' THEN 2 
                            WHEN 'MEDIUM' THEN 3 
                            WHEN 'LOW' THEN 4 
                            ELSE 5 
                        END,
                        a.created_at DESC
                    LIMIT ?
                """, (limit,)).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def insert(alert: Dict[str, Any], db_path: Optional[str] = None) -> None:
        with get_connection(db_path) as conn:
            conn.execute("""
                INSERT OR IGNORE INTO alerts (id, device_id, rule_id, severity, title, message, status, mitre_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert["id"],
                alert["device_id"],
                alert.get("rule_id"),
                alert["severity"],
                alert["title"],
                alert["message"],
                alert.get("status", "NEW"),
                alert.get("mitre_id"),
                alert.get("created_at", datetime.now(timezone.utc).isoformat())
            ))
            conn.commit()

    @staticmethod
    def acknowledge(alert_id: str, operator: str = "SOC-Analyst", db_path: Optional[str] = None) -> bool:
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_connection(db_path) as conn:
            cur = conn.execute("""
                UPDATE alerts
                SET status = 'ACKNOWLEDGED', acknowledged_at = ?
                WHERE id = ? AND status = 'NEW'
            """, (now_iso, alert_id))
            conn.commit()
            return cur.rowcount > 0

    @staticmethod
    def resolve(alert_id: str, note: str = "Remediated by SOC operator", db_path: Optional[str] = None) -> bool:
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_connection(db_path) as conn:
            cur = conn.execute("""
                UPDATE alerts
                SET status = 'RESOLVED', resolved_at = ?, resolution_note = ?
                WHERE id = ?
            """, (now_iso, note, alert_id))
            conn.commit()
            return cur.rowcount > 0


class TelemetryRepository:
    @staticmethod
    def insert_sample(sample: Dict[str, Any], db_path: Optional[str] = None) -> None:
        with get_connection(db_path) as conn:
            conn.execute("""
                INSERT INTO telemetry_samples (
                    device_id, timestamp, cpu_percent, memory_percent, latency_ms,
                    packet_loss_percent, bandwidth_in_mbps, bandwidth_out_mbps, packets_per_sec
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                sample["device_id"],
                sample.get("timestamp", datetime.now(timezone.utc).isoformat()),
                sample["cpu_percent"],
                sample["memory_percent"],
                sample["latency_ms"],
                sample["packet_loss_percent"],
                sample["bandwidth_in_mbps"],
                sample["bandwidth_out_mbps"],
                sample["packets_per_sec"]
            ))
            conn.commit()

    @staticmethod
    def get_latest_samples(limit: int = 15, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        with get_connection(db_path) as conn:
            rows = conn.execute("""
                SELECT t.*, d.hostname, d.role
                FROM telemetry_samples t
                JOIN devices d ON t.device_id = d.id
                WHERE t.id IN (
                    SELECT MAX(id) FROM telemetry_samples GROUP BY device_id
                )
                ORDER BY d.tier, d.hostname
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get_device_history(device_id: str, limit: int = 60, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        with get_connection(db_path) as conn:
            rows = conn.execute("""
                SELECT * FROM telemetry_samples
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (device_id, limit)).fetchall()
            return [dict(r) for r in reversed(rows)]
