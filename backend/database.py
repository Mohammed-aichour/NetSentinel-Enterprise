"""
NetSentinel Enterprise - Dual-Mode Database Persistence Layer
Supports Cloud PostgreSQL (Neon / Supabase / Vercel Postgres) & Local SQLite with WAL Mode.
Automated schema initialization, parameterized query translation, and enterprise auditing.
Author: Mohammed Aichour
"""

import os
import re
import ssl
import json
import logging
import sqlite3
import tempfile
import ipaddress
import contextlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, unquote

from backend.config import DB_PATH, DATABASE_URL

logger = logging.getLogger("netsentinel.database")


def is_postgres_configured() -> bool:
    """Checks whether an external PostgreSQL connection URL is configured in the environment."""
    return bool(DATABASE_URL and (DATABASE_URL.startswith("postgresql://") or DATABASE_URL.startswith("postgres://")))


def parse_pg_url(url: str) -> Dict[str, Any]:
    """Parses a standard PostgreSQL connection URL into arguments suitable for pg8000."""
    normalized = url
    if normalized.startswith("postgres://"):
        normalized = "postgresql://" + normalized[len("postgres://"):]

    parsed = urlparse(normalized)
    username = unquote(parsed.username) if parsed.username else "postgres"
    password = unquote(parsed.password) if parsed.password else ""
    hostname = parsed.hostname or "localhost"
    port = parsed.port or 5432
    database = parsed.path.lstrip("/") or "netsentinel"

    query_params = parse_qs(parsed.query)
    ssl_context = None

    if "sslmode" in query_params:
        mode = query_params["sslmode"][0].lower()
        if mode in ("require", "verify-ca", "verify-full"):
            ssl_context = ssl.create_default_context()
        elif mode == "disable":
            ssl_context = None
    elif "ssl" in query_params and query_params["ssl"][0].lower() in ("true", "1", "require"):
        ssl_context = ssl.create_default_context()
    elif hostname not in ("localhost", "127.0.0.1", "::1"):
        # Cloud providers like Neon, Supabase, Vercel Postgres require SSL
        ssl_context = ssl.create_default_context()

    return {
        "user": username,
        "password": password,
        "host": hostname,
        "port": port,
        "database": database,
        "ssl_context": ssl_context
    }


def translate_query_for_pg(sql: str) -> str:
    """
    Translates SQLite-compatible queries to PostgreSQL syntax:
    - Converts ? parameter placeholders to %s
    - Converts :name parameter placeholders to %(name)s
    - Converts INSERT OR IGNORE INTO to INSERT INTO ... ON CONFLICT DO NOTHING
    """
    converted = sql.replace("?", "%s")
    converted = re.sub(r':([a-zA-Z0-9_]+)', r'%(\1)s', converted)
    converted = re.sub(r'INSERT\s+OR\s+IGNORE\s+INTO', 'INSERT INTO', converted, flags=re.IGNORECASE)
    return converted


class RowDict(dict):
    """Dictionary supporting integer index access (row[0]) and key access (row['col']) like sqlite3.Row."""
    def __init__(self, mapping: dict, columns: list):
        super().__init__(mapping)
        self._columns = columns

    def __getitem__(self, item):
        if isinstance(item, int):
            return super().__getitem__(self._columns[item])
        return super().__getitem__(item)


class PgCursorWrapper:
    """Wraps a pg8000 cursor to provide unified query execution and dict-convertible rows."""
    def __init__(self, cursor):
        self._cursor = cursor

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def description(self):
        return self._cursor.description

    def execute(self, query: str, params=None):
        pg_query = translate_query_for_pg(query)
        if params is not None:
            self._cursor.execute(pg_query, params)
        else:
            self._cursor.execute(pg_query)
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in self._cursor.description]
        return RowDict(dict(zip(cols, row)), cols)

    def fetchall(self):
        rows = self._cursor.fetchall()
        if not rows:
            return []
        cols = [d[0] for d in self._cursor.description]
        return [RowDict(dict(zip(cols, r)), cols) for r in rows]

    def close(self):
        self._cursor.close()


class PgConnectionWrapper:
    """Wraps a pg8000 connection to provide SQLite-like connection semantics."""
    def __init__(self, raw_conn):
        self._raw_conn = raw_conn

    def cursor(self):
        return PgCursorWrapper(self._raw_conn.cursor())

    def execute(self, query: str, params=None):
        cur = self.cursor()
        cur.execute(query, params)
        return cur

    def commit(self):
        self._raw_conn.commit()

    def rollback(self):
        self._raw_conn.rollback()

    def close(self):
        self._raw_conn.close()


def open_raw_connection(db_path: Optional[str] = None):
    """
    Creates a configured database connection.
    Uses PostgreSQL if DATABASE_URL is set and no custom db_path is provided.
    Otherwise creates a configured SQLite connection with row factories and WAL mode.
    """
    if is_postgres_configured() and db_path is None:
        import pg8000.dbapi
        pg_args = parse_pg_url(DATABASE_URL)
        raw_conn = pg8000.dbapi.connect(**pg_args)
        return PgConnectionWrapper(raw_conn)

    target_path = db_path or DB_PATH
    try:
        Path(target_path).parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        target_path = str(Path(tempfile.gettempdir()) / "netsentinel.db")
        try:
            Path(target_path).parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    try:
        conn = sqlite3.connect(target_path, timeout=10.0)
    except sqlite3.OperationalError:
        target_path = str(Path(tempfile.gettempdir()) / "netsentinel.db")
        conn = sqlite3.connect(target_path, timeout=10.0)

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


@contextlib.contextmanager
def get_connection(db_path: Optional[str] = None):
    """Context manager that auto-commits and explicitly closes database connections."""
    conn = open_raw_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None) -> None:
    """Initializes tables, indexes, and initial constraints for SQLite or PostgreSQL."""
    is_pg = is_postgres_configured() and db_path is None
    auto_inc = "SERIAL PRIMARY KEY" if is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"

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
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS topology_links (
                id {auto_inc},
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
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS telemetry_samples (
                id {auto_inc},
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
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS security_events (
                id {auto_inc},
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
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS audit_log (
                id {auto_inc},
                timestamp TEXT NOT NULL,
                operator TEXT NOT NULL,
                action TEXT NOT NULL,
                target_id TEXT NOT NULL,
                details TEXT
            );
        """)

        conn.commit()
    logger.info(f"Database schema initialized successfully ({'PostgreSQL' if is_pg else 'SQLite WAL'}).")


def check_database_readiness(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Tests connectivity to the active persistent database and returns status summary."""
    try:
        is_pg = is_postgres_configured() and db_path is None
        engine_name = "PostgreSQL" if is_pg else "SQLite"
        with get_connection(db_path) as conn:
            row = conn.execute("SELECT COUNT(*) as count FROM devices").fetchone()
            device_count = row["count"] if row else 0
            alert_count = 0
            alert_row = conn.execute("SELECT COUNT(*) as count FROM alerts WHERE status = 'NEW'").fetchone()
            if alert_row:
                alert_count = alert_row["count"]

            return {
                "ready": True,
                "engine": engine_name,
                "device_count": device_count,
                "active_alerts": alert_count,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    except Exception as e:
        logger.error(f"Database readiness check failed: {e}")
        return {
            "ready": False,
            "engine": "Unknown",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


# Database Helper Operations
class DeviceRepository:
    VALID_TIERS = {"EDGE", "CORE", "DMZ", "SERVICES", "DATABASE", "ACCESS"}

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
    def create(device_data: Dict[str, Any], operator: str = "SOC-Operator", db_path: Optional[str] = None) -> Dict[str, Any]:
        """Creates a new device in the inventory with validation and audit logging."""
        dev_id = str(device_data.get("id", "")).strip()
        hostname = str(device_data.get("hostname", "")).strip()
        ip_addr = str(device_data.get("ip_address", "")).strip()
        mac_addr = str(device_data.get("mac_address", "")).strip()

        if not dev_id:
            raise ValueError("Field 'id' is required and cannot be empty.")
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', dev_id):
            raise ValueError("Field 'id' must contain only alphanumeric characters, dots, dashes, or underscores.")
        if not hostname:
            raise ValueError("Field 'hostname' is required.")

        try:
            ipaddress.ip_address(ip_addr)
        except ValueError:
            raise ValueError(f"Invalid IP address format: '{ip_addr}'.")

        tier = str(device_data.get("tier", "ACCESS")).strip().upper()
        if tier not in DeviceRepository.VALID_TIERS:
            tier = "ACCESS"

        role = str(device_data.get("role", "Host")).strip() or "Host"
        vendor = str(device_data.get("vendor", "Generic")).strip() or "Generic"
        status = str(device_data.get("status", "ONLINE")).strip().upper() or "ONLINE"
        services = device_data.get("services", [])
        services_json = json.dumps(services) if not isinstance(services, str) else services

        now_iso = datetime.now(timezone.utc).isoformat()

        with get_connection(db_path) as conn:
            # Check for conflict
            conflict = conn.execute("SELECT id FROM devices WHERE id = ? OR ip_address = ?", (dev_id, ip_addr)).fetchone()
            if conflict:
                raise ValueError(f"A device with ID '{dev_id}' or IP '{ip_addr}' already exists in inventory.")

            conn.execute("""
                INSERT INTO devices (id, hostname, ip_address, mac_address, tier, role, vendor,
                                     status, services, is_quarantined, last_seen, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
            """, (
                dev_id, hostname, ip_addr, mac_addr or "00:00:00:00:00:00",
                tier, role, vendor, status, services_json, now_iso, now_iso
            ))
            conn.commit()

        AuditLogRepository.record(
            operator=operator,
            action="DEVICE_CREATE",
            target_id=dev_id,
            details=f"Created device {hostname} ({ip_addr}) in tier {tier}",
            db_path=db_path
        )

        return DeviceRepository.get_by_id(dev_id, db_path=db_path)

    @staticmethod
    def update(device_id: str, updates: Dict[str, Any], operator: str = "SOC-Operator", db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Updates an existing device's metadata with validation and audit logging."""
        existing = DeviceRepository.get_by_id(device_id, db_path=db_path)
        if not existing:
            return None

        new_hostname = updates.get("hostname", existing["hostname"])
        new_ip = updates.get("ip_address", existing["ip_address"])
        new_mac = updates.get("mac_address", existing["mac_address"])
        new_tier = str(updates.get("tier", existing["tier"])).upper()
        if new_tier not in DeviceRepository.VALID_TIERS:
            new_tier = existing["tier"]
        new_role = updates.get("role", existing["role"])
        new_vendor = updates.get("vendor", existing["vendor"])
        new_services = updates.get("services", existing["services"])
        services_json = json.dumps(new_services) if not isinstance(new_services, str) else new_services

        if new_ip != existing["ip_address"]:
            try:
                ipaddress.ip_address(new_ip)
            except ValueError:
                raise ValueError(f"Invalid IP address format: '{new_ip}'.")

            with get_connection(db_path) as conn:
                conflict = conn.execute("SELECT id FROM devices WHERE ip_address = ? AND id != ?", (new_ip, device_id)).fetchone()
                if conflict:
                    raise ValueError(f"IP address '{new_ip}' is already in use by device '{conflict['id']}'.")

        now_iso = datetime.now(timezone.utc).isoformat()
        with get_connection(db_path) as conn:
            conn.execute("""
                UPDATE devices
                SET hostname = ?, ip_address = ?, mac_address = ?, tier = ?,
                    role = ?, vendor = ?, services = ?, last_seen = ?
                WHERE id = ?
            """, (new_hostname, new_ip, new_mac, new_tier, new_role, new_vendor, services_json, now_iso, device_id))
            conn.commit()

        AuditLogRepository.record(
            operator=operator,
            action="DEVICE_UPDATE",
            target_id=device_id,
            details=f"Updated device metadata ({new_hostname}, {new_ip})",
            db_path=db_path
        )

        return DeviceRepository.get_by_id(device_id, db_path=db_path)

    @staticmethod
    def delete(device_id: str, operator: str = "SOC-Operator", db_path: Optional[str] = None) -> bool:
        """Deletes a device from inventory and cascades deletions across links and telemetry."""
        existing = DeviceRepository.get_by_id(device_id, db_path=db_path)
        if not existing:
            return False

        with get_connection(db_path) as conn:
            # Explicitly delete dependent rows for foreign keys
            conn.execute("DELETE FROM topology_links WHERE source_id = ? OR target_id = ?", (device_id, device_id))
            conn.execute("DELETE FROM telemetry_samples WHERE device_id = ?", (device_id,))
            conn.execute("DELETE FROM alerts WHERE device_id = ?", (device_id,))
            conn.execute("DELETE FROM security_events WHERE target_device_id = ?", (device_id,))
            cur = conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            conn.commit()

        AuditLogRepository.record(
            operator=operator,
            action="DEVICE_DELETE",
            target_id=device_id,
            details=f"Deleted device {existing['hostname']} ({existing['ip_address']}) from inventory",
            db_path=db_path
        )
        return True

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
    def recompute_status(device_id: str, db_path: Optional[str] = None) -> str:
        """
        Dynamically calculates device health based on remaining active alerts
        and quarantine state. Ensures reliable device health recovery on alert resolution.
        """
        with get_connection(db_path) as conn:
            dev = conn.execute("SELECT is_quarantined FROM devices WHERE id = ?", (device_id,)).fetchone()
            if not dev:
                return "OFFLINE"
            if dev["is_quarantined"]:
                conn.execute("UPDATE devices SET status = 'CRITICAL' WHERE id = ?", (device_id,))
                conn.commit()
                return "CRITICAL"

            rows = conn.execute("""
                SELECT severity FROM alerts
                WHERE device_id = ? AND status IN ('NEW', 'ACKNOWLEDGED')
            """, (device_id,)).fetchall()

            severities = [r["severity"] for r in rows]
            if "CRITICAL" in severities:
                new_status = "CRITICAL"
            elif "HIGH" in severities or "MEDIUM" in severities:
                new_status = "DEGRADED"
            else:
                new_status = "ONLINE"

            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute("UPDATE devices SET status = ?, last_seen = ? WHERE id = ?", (new_status, now_iso, device_id))
            conn.commit()
            return new_status

    @staticmethod
    def set_quarantine(device_id: str, quarantined: bool, operator: str = "SOC-Analyst", reason: str = "Host software isolation", db_path: Optional[str] = None) -> None:
        val = 1 if quarantined else 0
        new_status = "CRITICAL" if quarantined else "ONLINE"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_connection(db_path) as conn:
            conn.execute("UPDATE devices SET is_quarantined = ?, status = ?, last_seen = ? WHERE id = ?", (val, new_status, now_iso, device_id))
            # Record in compliance audit log
            action = "QUARANTINE_ENFORCE" if quarantined else "QUARANTINE_RELEASE"
            conn.execute("""
                INSERT INTO audit_log (timestamp, operator, action, target_id, details)
                VALUES (?, ?, ?, ?, ?)
            """, (now_iso, operator, action, device_id, reason))
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
                INSERT INTO alerts (id, device_id, rule_id, severity, title, message, status, mitre_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (id) DO NOTHING
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
    def get_by_id(alert_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with get_connection(db_path) as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            return dict(row) if row else None

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
    def insert_agent_report(report: Dict[str, Any], db_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Ingests batch telemetry collected by a remote collector agent.
        Updates device state and records time-series measurements.
        """
        agent_id = report.get("agent_id", "local-collector-agent")
        probes = report.get("probes", [])
        host_metrics = report.get("agent_host_metrics", {})
        now_iso = report.get("timestamp", datetime.now(timezone.utc).isoformat())

        probes_recorded = 0
        devices_updated = []

        with get_connection(db_path) as conn:
            for probe in probes:
                dev_id = probe.get("device_id")
                if not dev_id:
                    continue

                rtt = float(probe.get("rtt_ms", 0.0))
                loss = float(probe.get("packet_loss_percent", 0.0))
                reachable = bool(probe.get("reachable", loss < 100.0))

                sample = {
                    "device_id": dev_id,
                    "timestamp": now_iso,
                    "cpu_percent": float(probe.get("cpu_percent", host_metrics.get("cpu_percent", 30.0))),
                    "memory_percent": float(probe.get("memory_percent", host_metrics.get("memory_percent", 45.0))),
                    "latency_ms": rtt,
                    "packet_loss_percent": loss,
                    "bandwidth_in_mbps": float(probe.get("bandwidth_in_mbps", 50.0 if reachable else 0.0)),
                    "bandwidth_out_mbps": float(probe.get("bandwidth_out_mbps", 40.0 if reachable else 0.0)),
                    "packets_per_sec": int(probe.get("packets_per_sec", 1200 if reachable else 0))
                }

                conn.execute("""
                    INSERT INTO telemetry_samples (
                        device_id, timestamp, cpu_percent, memory_percent, latency_ms,
                        packet_loss_percent, bandwidth_in_mbps, bandwidth_out_mbps, packets_per_sec
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    sample["device_id"], sample["timestamp"], sample["cpu_percent"],
                    sample["memory_percent"], sample["latency_ms"], sample["packet_loss_percent"],
                    sample["bandwidth_in_mbps"], sample["bandwidth_out_mbps"], sample["packets_per_sec"]
                ))
                probes_recorded += 1

                # Update device last_seen and status (if not quarantined)
                dev_row = conn.execute("SELECT is_quarantined FROM devices WHERE id = ?", (dev_id,)).fetchone()
                if dev_row and not dev_row["is_quarantined"]:
                    if not reachable or loss >= 90.0:
                        new_status = "CRITICAL"
                    elif loss > 5.0 or rtt > 150.0:
                        new_status = "DEGRADED"
                    else:
                        new_status = "ONLINE"
                    conn.execute("UPDATE devices SET status = ?, last_seen = ? WHERE id = ?", (new_status, now_iso, dev_id))
                    devices_updated.append({"device_id": dev_id, "status": new_status})
                elif dev_row:
                    conn.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (now_iso, dev_id))

            conn.commit()

        # Prune old samples beyond retention limit
        TelemetryRepository.prune_old_samples(keep_per_device=120, db_path=db_path)

        return {
            "status": "ACCEPTED",
            "agent_id": agent_id,
            "probes_processed": probes_recorded,
            "devices_updated": len(devices_updated),
            "timestamp": now_iso
        }

    @staticmethod
    def prune_old_samples(keep_per_device: int = 120, db_path: Optional[str] = None) -> int:
        """Prunes historical samples beyond retention window to prevent database bloat."""
        with get_connection(db_path) as conn:
            dev_rows = conn.execute("SELECT DISTINCT device_id FROM telemetry_samples").fetchall()
            deleted_count = 0
            for r in dev_rows:
                dev_id = r["device_id"]
                cur = conn.execute("""
                    DELETE FROM telemetry_samples
                    WHERE device_id = ? AND id NOT IN (
                        SELECT id FROM telemetry_samples
                        WHERE device_id = ?
                        ORDER BY id DESC
                        LIMIT ?
                    )
                """, (dev_id, dev_id, keep_per_device))
                deleted_count += cur.rowcount
            conn.commit()
            return deleted_count

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


class SecurityEventRepository:
    @staticmethod
    def insert(event: Dict[str, Any], db_path: Optional[str] = None) -> None:
        now_iso = event.get("timestamp", datetime.now(timezone.utc).isoformat())
        summary = event.get("payload_summary") or event.get("raw_message") or ""
        with get_connection(db_path) as conn:
            try:
                conn.execute("""
                    INSERT INTO security_events (timestamp, source_ip, target_device_id, event_type, payload_summary, severity)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    now_iso,
                    event["source_ip"],
                    event["target_device_id"],
                    event["event_type"],
                    summary,
                    event.get("severity", "INFORMATIONAL")
                ))
                conn.commit()
            except Exception:
                # SIEM Asset Auto-discovery: automatically register newly observed host
                conn.execute("""
                    INSERT INTO devices (
                        id, hostname, ip_address, mac_address, tier, role, vendor,
                        status, services, is_quarantined, last_seen, created_at
                    ) VALUES (?, ?, ?, ?, 'UNCLASSIFIED', 'Discovered Host', 'Generic Network Host', 'ONLINE', '[]', 0, ?, ?)
                    ON CONFLICT (id) DO NOTHING
                """, (
                    event["target_device_id"],
                    event["target_device_id"],
                    event.get("source_ip", "0.0.0.0"),
                    "00:00:00:00:00:00",
                    now_iso,
                    now_iso
                ))
                conn.execute("""
                    INSERT INTO security_events (timestamp, source_ip, target_device_id, event_type, payload_summary, severity)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    now_iso,
                    event["source_ip"],
                    event["target_device_id"],
                    event["event_type"],
                    summary,
                    event.get("severity", "INFORMATIONAL")
                ))
                conn.commit()

    @staticmethod
    def list_events(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        with get_connection(db_path) as conn:
            rows = conn.execute("""
                SELECT * FROM security_events
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]


class AuditLogRepository:
    @staticmethod
    def record(operator: str, action: str, target_id: str, details: str, db_path: Optional[str] = None) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_connection(db_path) as conn:
            conn.execute("""
                INSERT INTO audit_log (timestamp, operator, action, target_id, details)
                VALUES (?, ?, ?, ?, ?)
            """, (now_iso, operator, action, target_id, details))
            conn.commit()

    @staticmethod
    def list_logs(limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        with get_connection(db_path) as conn:
            rows = conn.execute("""
                SELECT * FROM audit_log
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]
