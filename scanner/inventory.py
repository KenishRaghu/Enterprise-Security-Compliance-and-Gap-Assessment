"""Hardware/software inventory: platform + psutil + OS-specific package listing."""
from __future__ import annotations

import csv
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import psutil

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "output"
COLLECTOR_VERSION = "1.0.0"


def _sh(cmd: str, timeout: int = 120) -> str:
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except (subprocess.TimeoutExpired, OSError) as e:
        return str(e)


def _sw_list() -> List[str]:
    sysname = platform.system()
    if sysname == "Darwin":
        raw = _sh("system_profiler SPApplicationsDataType -json 2>/dev/null", timeout=180)
        try:
            data = json.loads(raw)
            apps = data.get("SPApplicationsDataType", [])
            names = []
            for a in apps[:400]:
                n = a.get("_name") or a.get("path")
                if n:
                    names.append(str(n))
            return sorted(set(names))[:350]
        except json.JSONDecodeError:
            return [raw[:500]]
    if sysname == "Linux":
        out = _sh("dpkg -l 2>/dev/null | awk 'NR>5{print $2}' | head -n 400")
        if out.strip():
            return out.strip().splitlines()
        out = _sh("rpm -qa 2>/dev/null | head -n 400")
        return out.strip().splitlines() if out.strip() else ["no dpkg/rpm list"]
    if sysname == "Windows":
        out = _sh("wmic product get name 2>nul")
        lines = [ln.strip() for ln in out.splitlines() if ln.strip() and ln.strip().lower() != "name"]
        return lines[:400] or ["wmic empty or unavailable"]
    return ["unknown OS"]


def collect() -> Dict[str, Any]:
    macs = []
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if getattr(a, "family", None) == psutil.AF_LINK and a.address:
                macs.append(f"{name}:{a.address}")
    parts = []
    for p in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(p.mountpoint)
            parts.append({"device": p.device, "mountpoint": p.mountpoint, "fstype": p.fstype, "total_gb": round(u.total / 1e9, 2)})
        except OSError:
            parts.append({"device": p.device, "mountpoint": p.mountpoint, "fstype": p.fstype, "total_gb": None})
    header = {
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "collector_version": COLLECTOR_VERSION,
        "host_identifier": platform.node(),
        "platform": platform.platform(),
    }
    body = {
        "hardware": {
            "hostname": platform.node(),
            "os_version": platform.platform(),
            "cpu_model": platform.processor() or "unknown",
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "ram_total_gb": round(psutil.virtual_memory().total / 1e9, 2),
            "disk_partitions": parts,
            "mac_addresses": macs,
        },
        "software": {"installed_packages_sample": _sw_list()},
    }
    return {"header": header, "inventory": body}


def write_outputs(data: Dict[str, Any]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "inventory.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    h, inv = data["header"], data["inventory"]
    hw, sw = inv["hardware"], inv["software"]
    rows: List[List[str]] = []
    rows.append(["section", "attribute", "value"])
    rows.append(["header", "collected_at_utc", h["collected_at_utc"]])
    rows.append(["header", "collector_version", h["collector_version"]])
    rows.append(["header", "host_identifier", h["host_identifier"]])
    rows.append(["header", "platform_summary", h["platform"]])
    rows.append(["hardware", "hostname", hw["hostname"]])
    rows.append(["hardware", "os_version", hw["os_version"]])
    rows.append(["hardware", "cpu_model", hw["cpu_model"]])
    rows.append(["hardware", "cpu_count_logical", str(hw["cpu_count_logical"])])
    rows.append(["hardware", "cpu_count_physical", str(hw["cpu_count_physical"])])
    rows.append(["hardware", "ram_total_gb", str(hw["ram_total_gb"])])
    for m in hw["mac_addresses"]:
        rows.append(["hardware", "mac", m])
    for p in hw["disk_partitions"]:
        rows.append(["hardware", "disk_partition", json.dumps(p, separators=(",", ":"))])
    for pkg in sw["installed_packages_sample"]:
        rows.append(["software", "installed_package", pkg])
    with (OUT_DIR / "inventory.csv").open("w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)


def run_inventory() -> Dict[str, Any]:
    data = collect()
    write_outputs(data)
    return data
