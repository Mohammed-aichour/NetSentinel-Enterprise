"""
NetSentinel Enterprise - Database Persistence & Dual-Mode Unit Tests
Verifies SQLite WAL mode, PostgreSQL connection parsing, query translation,
full Device CRUD repository methods, and agent report ingestion.
Author: Mohammed Aichour
"""

import os
import unittest
import tempfile
from pathlib import Path
from backend.database import (
    init_db,
    open_raw_connection,
    check_database_readiness,
    parse_pg_url,
    translate_query_for_pg,
    RowDict,
    DeviceRepository,
    TelemetryRepository,
    AuditLogRepository
)


class TestDatabasePersistence(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test_persistence.db")
        init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sqlite_wal_mode_and_readiness(self):
        """Verifies SQLite initializes in WAL mode and readiness check reports success."""
        conn = open_raw_connection(self.db_path)
        wal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        fk_mode = conn.execute("PRAGMA foreign_keys;").fetchone()[0]
        conn.close()

        self.assertEqual(wal_mode.upper(), "WAL")
        self.assertEqual(fk_mode, 1)

        readiness = check_database_readiness(self.db_path)
        self.assertTrue(readiness["ready"])
        self.assertEqual(readiness["engine"], "SQLite")
        self.assertEqual(readiness["device_count"], 0)

    def test_postgres_url_parser(self):
        """Verifies parsing of standard and cloud PostgreSQL connection URLs."""
        url = "postgresql://secops_user:p%40ssword_123@ep-proud-pool-42.eu-central-1.aws.neon.tech:5432/netsentinel_db?sslmode=require"
        parsed = parse_pg_url(url)

        self.assertEqual(parsed["user"], "secops_user")
        self.assertEqual(parsed["password"], "p@ssword_123")
        self.assertEqual(parsed["host"], "ep-proud-pool-42.eu-central-1.aws.neon.tech")
        self.assertEqual(parsed["port"], 5432)
        self.assertEqual(parsed["database"], "netsentinel_db")
        self.assertIsNotNone(parsed["ssl_context"])

        # Local postgres with disabled ssl
        local_url = "postgres://postgres:secret@localhost:5433/localdb?sslmode=disable"
        local_parsed = parse_pg_url(local_url)
        self.assertEqual(local_parsed["port"], 5433)
        self.assertIsNone(local_parsed["ssl_context"])

    def test_query_translation_for_postgres(self):
        """Verifies SQLite parameter syntax converts to PostgreSQL parameter formats."""
        q1 = "SELECT * FROM devices WHERE id = ? AND status = ?"
        translated1 = translate_query_for_pg(q1)
        self.assertEqual(translated1, "SELECT * FROM devices WHERE id = %s AND status = %s")

        q2 = "INSERT INTO devices (id, hostname) VALUES (:id, :hostname)"
        translated2 = translate_query_for_pg(q2)
        self.assertEqual(translated2, "INSERT INTO devices (id, hostname) VALUES (%(id)s, %(hostname)s)")

        q3 = "INSERT OR IGNORE INTO alerts (id, title) VALUES (?, ?)"
        translated3 = translate_query_for_pg(q3)
        self.assertIn("INSERT INTO alerts", translated3)
        self.assertNotIn("OR IGNORE", translated3)

    def test_row_dict_semantics(self):
        """Verifies RowDict behaves identically to sqlite3.Row for dict conversions and indexing."""
        columns = ["id", "hostname", "status"]
        mapping = {"id": "rtr-core-01", "hostname": "core.corp", "status": "ONLINE"}
        row = RowDict(mapping, columns)

        self.assertEqual(row["hostname"], "core.corp")
        self.assertEqual(row[1], "core.corp")
        self.assertEqual(row[0], "rtr-core-01")
        self.assertDictEqual(dict(row), mapping)

    def test_device_crud_lifecycle(self):
        """Verifies Create, Read, Update, and Delete operations for device inventory."""
        # 1. Create
        dev_data = {
            "id": "srv-app-01",
            "hostname": "app01.corp.internal",
            "ip_address": "10.0.5.25",
            "mac_address": "00:50:56:AB:CD:01",
            "tier": "SERVICES",
            "role": "Application Gateway",
            "vendor": "Alpine Linux 3.20",
            "services": [{"port": 8080, "name": "HTTP-API"}]
        }
        created = DeviceRepository.create(dev_data, operator="Lead-Engineer", db_path=self.db_path)
        self.assertEqual(created["id"], "srv-app-01")
        self.assertEqual(created["status"], "ONLINE")
        self.assertFalse(created["is_quarantined"])
        self.assertEqual(len(created["services"]), 1)

        # Verify audit log recorded creation
        logs = AuditLogRepository.list_logs(db_path=self.db_path)
        self.assertTrue(any(l["action"] == "DEVICE_CREATE" and l["target_id"] == "srv-app-01" for l in logs))

        # 2. Prevent duplicate ID or IP
        with self.assertRaises(ValueError):
            DeviceRepository.create(dev_data, db_path=self.db_path)

        with self.assertRaises(ValueError):
            duplicate_ip = dict(dev_data)
            duplicate_ip["id"] = "srv-app-02"
            DeviceRepository.create(duplicate_ip, db_path=self.db_path)

        # 3. Read
        fetched = DeviceRepository.get_by_id("srv-app-01", db_path=self.db_path)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["hostname"], "app01.corp.internal")

        # 4. Update
        updated = DeviceRepository.update(
            "srv-app-01",
            {"hostname": "app01-prod.corp.internal", "role": "Primary App Gateway"},
            operator="Lead-Engineer",
            db_path=self.db_path
        )
        self.assertEqual(updated["hostname"], "app01-prod.corp.internal")
        self.assertEqual(updated["role"], "Primary App Gateway")

        # 5. Delete
        del_success = DeviceRepository.delete("srv-app-01", operator="Lead-Engineer", db_path=self.db_path)
        self.assertTrue(del_success)
        self.assertIsNone(DeviceRepository.get_by_id("srv-app-01", db_path=self.db_path))

    def test_agent_telemetry_batch_ingestion(self):
        """Verifies ingestion of telemetry batch reports sent by the remote collector agent."""
        # Seed a test device
        DeviceRepository.create({
            "id": "switch-edge-01",
            "hostname": "sw-edge.corp.internal",
            "ip_address": "10.0.1.10",
            "tier": "EDGE",
            "role": "Perimeter Switch"
        }, db_path=self.db_path)

        report = {
            "agent_id": "test-agent-lan-01",
            "agent_host_metrics": {"cpu_percent": 18.0, "memory_percent": 42.0},
            "probes": [
                {
                    "device_id": "switch-edge-01",
                    "reachable": True,
                    "rtt_ms": 1.45,
                    "packet_loss_percent": 0.0,
                    "cpu_percent": 22.0,
                    "memory_percent": 35.0
                }
            ]
        }

        res = TelemetryRepository.insert_agent_report(report, db_path=self.db_path)
        self.assertEqual(res["status"], "ACCEPTED")
        self.assertEqual(res["probes_processed"], 1)

        history = TelemetryRepository.get_device_history("switch-edge-01", limit=10, db_path=self.db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["latency_ms"], 1.45)


if __name__ == "__main__":
    unittest.main()
