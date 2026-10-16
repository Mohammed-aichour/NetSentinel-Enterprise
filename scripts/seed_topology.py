#!/usr/bin/env python3
"""
NetSentinel Enterprise - Database & Topology Seeder Script
Initializes SQLite schema and populates the enterprise multi-tier network topology.
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database import init_db
from backend.engine.simulator import seed_enterprise_topology


def main():
    print("[*] Initializing NetSentinel Database schema...")
    init_db()
    print("[*] Seeding UniversiaCorp enterprise infrastructure nodes...")
    seed_enterprise_topology()
    print("[+] Enterprise topology seeded successfully.")


if __name__ == "__main__":
    main()
