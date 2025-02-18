"""CLI entry: inventory, gap scan, GPO mapping, SIEM dashboard, or full pipeline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scanner import gap_scanner, gpo_recommender, inventory
from siem import dashboard as siem_dashboard

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "output"


def cmd_inventory(_: argparse.Namespace) -> None:
    inventory.run_inventory()
    print("Wrote output/inventory.json and output/inventory.csv")


def cmd_scan(_: argparse.Namespace) -> None:
    gap_scanner.run_scan()
    print("Wrote output/gap_report.json and output/gap_report.txt")


def cmd_recommend(_: argparse.Namespace) -> None:
    gpo_recommender.run_recommend()
    print("Wrote output/gpo_recommendations.md")


def cmd_dashboard(_: argparse.Namespace) -> None:
    siem_dashboard.run_dashboard()
    print("Wrote output/siem_dashboard.png and output/remediation_priority.csv")


def cmd_all(_: argparse.Namespace) -> None:
    cmd_inventory(_)
    cmd_scan(_)
    cmd_recommend(_)
    cmd_dashboard(_)
    gap = json.loads((OUT / "gap_report.json").read_text(encoding="utf-8"))
    inv = json.loads((OUT / "inventory.json").read_text(encoding="utf-8"))
    print("\n=== Pipeline summary ===")
    print(f"Host: {inv['header']['host_identifier']}")
    print(f"Collector: {inv['header']['collector_version']} @ {inv['header']['collected_at_utc']}")
    print("\nRule results:")
    print(f"{'Rule ID':<12} {'Status':<18} {'Severity':<8} Description")
    print("-" * 72)
    for r in gap:
        d = (r.get("description") or "")[:36]
        print(f"{r['rule_id']:<12} {r['status']:<18} {r['severity']:<8} {d}")
    print("\nArtifacts:")
    for name in ("inventory.json", "inventory.csv", "gap_report.json", "gap_report.txt", "gpo_recommendations.md", "siem_dashboard.png", "remediation_priority.csv"):
        p = OUT / name
        print(f"  {name}: {'ok' if p.exists() else 'MISSING'}")


def main() -> None:
    p = argparse.ArgumentParser(description="Local compliance assessment toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("inventory", help="Collect HW/SW inventory to CSV and JSON").set_defaults(func=cmd_inventory)
    sub.add_parser("scan", help="Run ISO 27001-aligned gap checks").set_defaults(func=cmd_scan)
    sub.add_parser("recommend", help="Build GPO markdown from gap_report.json").set_defaults(func=cmd_recommend)
    sub.add_parser("dashboard", help="SIEM charts and remediation CSV").set_defaults(func=cmd_dashboard)
    sub.add_parser("all", help="Run inventory, scan, recommend, dashboard").set_defaults(func=cmd_all)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
