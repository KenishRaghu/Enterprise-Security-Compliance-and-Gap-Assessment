"""Matplotlib SIEM dashboard + weighted remediation priority CSV."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
(_mpl_cfg := ROOT / ".mplconfig").mkdir(exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(_mpl_cfg))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from siem.log_parser import load_alerts

OUT_DIR = ROOT / "output"
WEIGHT = {"HIGH": 5, "MEDIUM": 3, "LOW": 1}


def run_dashboard() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    df = load_alerts()
    df["day"] = df["timestamp"].dt.floor("D")
    df["sev_w"] = df["severity"].map(WEIGHT).fillna(0)

    daily = df.groupby("day").size()
    sev = df.groupby("severity").size()
    top_ip = df.groupby("source_ip").size().sort_values(ascending=False).head(10)
    types = df.groupby("alert_type").size()

    fig, axes = plt.subplots(2, 2, figsize=(11, 8))
    daily.plot(ax=axes[0, 0], color="#1f77b4")
    axes[0, 0].set_title("Alert count by day")
    axes[0, 0].set_xlabel("Date")
    axes[0, 0].set_ylabel("Count")

    sev.plot(kind="bar", ax=axes[0, 1], color=["#d62728", "#ff7f0e", "#2ca02c"])
    axes[0, 1].set_title("Alerts by severity")
    axes[0, 1].set_xlabel("Severity")
    axes[0, 1].set_ylabel("Count")

    top_ip.sort_values().plot(kind="barh", ax=axes[1, 0], color="#9467bd")
    axes[1, 0].set_title("Top 10 source IPs")
    axes[1, 0].set_xlabel("Alerts")

    types.plot(kind="pie", ax=axes[1, 1], autopct="%1.0f%%", startangle=90)
    axes[1, 1].set_ylabel("")
    axes[1, 1].set_title("Alert type distribution")

    plt.tight_layout()
    fig.savefig(OUT_DIR / "siem_dashboard.png", dpi=120)
    plt.close(fig)

    rem = df.groupby("asset_id")["sev_w"].sum().sort_values(ascending=False).reset_index()
    rem.columns = ["asset_id", "weighted_severity_score"]
    rem.to_csv(OUT_DIR / "remediation_priority.csv", index=False)
