"""Load and validate sample SIEM CSV for dashboard and remediation scoring."""
from __future__ import annotations

from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "data" / "sample_siem_alerts.csv"
COLS = ["timestamp", "source_ip", "alert_type", "severity", "asset_id", "status"]


def load_alerts() -> pd.DataFrame:
    df = pd.read_csv(CSV_PATH, parse_dates=["timestamp"])
    missing = set(COLS) - set(df.columns)
    if missing:
        raise ValueError(f"CSV missing columns: {missing}")
    return df
