#!/usr/bin/env python3
"""
NetSentinel Enterprise - CLI Cyber Attack Simulator
Usage:
  python scripts/simulate_attack.py --scenario ddos --target fw-edge-01
  python scripts/simulate_attack.py --scenario brute_force --target db-prod-pri
  python scripts/simulate_attack.py --scenario port_scan --target srv-proxy-01
  python scripts/simulate_attack.py --scenario link_flap --target sw-core-a
"""

import sys
import argparse
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.engine.correlator import EventCorrelator
from backend.engine.alert_manager import AlertManager
from backend.engine.simulator import CyberAttackSimulator


def main():
    parser = argparse.ArgumentParser(description="NetSentinel Enterprise - Attack Simulation CLI")
    parser.add_argument(
        "--scenario",
        choices=["ddos", "brute_force", "port_scan", "link_flap"],
        default="ddos",
        help="Attack scenario to execute"
    )
    parser.add_argument(
        "--target",
        default="fw-edge-01",
        help="Target device identifier"
    )

    args = parser.parse_args()

    correlator = EventCorrelator()
    alert_mgr = AlertManager()
    sim = CyberAttackSimulator(correlator, alert_mgr)

    print("=" * 60)
    print(f"[*] EXECUTING SIMULATION: {args.scenario.upper()} on {args.target}")
    print("=" * 60)

    if args.scenario == "ddos":
        res = sim.trigger_ddos_spike(target_id=args.target)
    elif args.scenario == "brute_force":
        res = sim.trigger_ssh_brute_force(target_id=args.target)
    elif args.scenario == "port_scan":
        res = sim.trigger_port_scan(target_id=args.target)
    elif args.scenario == "link_flap":
        res = sim.trigger_link_flap(device_id=args.target)

    print("[+] Attack injection complete.")
    print(f"[+] Result summary: {res}")
    print("[*] Check SOC Dashboard at http://localhost:8080/ to inspect alert escalation.")


if __name__ == "__main__":
    main()
