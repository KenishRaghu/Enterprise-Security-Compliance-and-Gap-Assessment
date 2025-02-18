"""Map gap_report.json FAIL rows to static Group Policy recommendations."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GAP = ROOT / "output" / "gap_report.json"
OUT = ROOT / "output" / "gpo_recommendations.md"

# rule_id -> (GPO path, recommended value, ISO control rationale)
FAIL_MAP = {
    "A.9.4.3": (
        "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Minimum password length",
        "14 characters",
        "A.9.4.3 — Enforce strong authentication secrets via centralized password length.",
    ),
    "A.8.20": (
        "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Defender Firewall\\Domain Profile\\Windows Defender Firewall: Protect all network connections",
        "Enabled",
        "A.8.20 — Network controls: require host firewall on managed endpoints.",
    ),
    "A.9.2.1": (
        "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\User Rights Assignment\\Deny log on locally",
        "Include Guest (and remove Guest from logon locally if assigned)",
        "A.9.2.1 — Restrict default accounts to reduce unauthorized access paths.",
    ),
    "A.8.16": (
        "Computer Configuration\\Policies\\Administrative Templates\\Network\\Lanman Workstation\\Enable insecure guest logons",
        "Disabled; disable SMB1 via optional features / server settings",
        "A.8.16 — Remove legacy protocols that expand lateral movement surface.",
    ),
    "A.12.6.1": (
        "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Windows Update\\Configure Automatic Updates",
        "Auto download and schedule install",
        "A.12.6.1 — Timely patching supports vulnerability management.",
    ),
    "A.8.5": (
        "User Configuration\\Policies\\Administrative Templates\\Control Panel\\Personalization\\Password protect the screen saver + Screen saver timeout",
        "Enabled + 10 minutes or less",
        "A.8.5 — Physical and environmental security for unattended workstations.",
    ),
    "A.10.1.1": (
        "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\BitLocker Drive Encryption\\Operating System Drives\\Require additional authentication at startup",
        "Enabled with TPM+PIN as appropriate",
        "A.10.1.1 — Cryptographic protection of data at rest on endpoints.",
    ),
    "A.8.20.2": (
        "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Remote Desktop Services\\Remote Desktop Session Host\\Connections\\Allow users to connect remotely by using Remote Desktop Services",
        "Disabled unless jump-host architecture",
        "A.8.20.2 — Reduce remote access exposure to trusted paths only.",
    ),
    "A.8.7": (
        "Computer Configuration\\Policies\\Administrative Templates\\Windows Components\\Microsoft Defender Antivirus\\Real-time Protection\\Turn on real-time protection",
        "Enabled",
        "A.8.7 — Malware defenses for endpoints processing organizational data.",
    ),
    "A.12.4.1": (
        "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Advanced Audit Policy Configuration\\Audit Policies\\Logon/Logoff\\Audit Logon",
        "Success and Failure",
        "A.12.4.1 — Generate evidence for security monitoring and investigations.",
    ),
    "A.8.22": (
        "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\User Rights Assignment\\Backup files and directories",
        "Restrict to dedicated backup operators only",
        "A.8.22 — Separation of duties for privileged backup operations.",
    ),
    "A.8.8": (
        "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Restricted Groups or GPO Preferences for local Administrators",
        "Tiered admin groups only",
        "A.8.8 — Limit privileged local accounts that bypass directory controls.",
    ),
    "A.8.19": (
        "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Windows Firewall with Advanced Security\\Outbound Rules",
        "Block unauthorized egress to sensitive ports",
        "A.8.19 — Control data flows leaving the endpoint.",
    ),
    "A.8.1": (
        "Computer Configuration\\Policies\\Administrative Templates\\Network\\Windows Connection Manager\\Prohibit connection to non-domain networks when connected to domain authenticated network",
        "Enabled where applicable",
        "A.8.1 — Reduce dual-homed bypass of corporate network policy.",
    ),
    "A.12.3.1": (
        "Computer Configuration\\Policies\\Administrative Templates\\System\\Filesystem\\NTFS\\Do not compress all NTFS volumes",
        "As per backup vendor; pair with Windows Backup / agent GPO",
        "A.12.3.1 — Information backup availability and integrity.",
    ),
}


def run_recommend() -> str:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    if not GAP.exists():
        text = "# GPO Recommendations\n\nRun `python main.py scan` first to produce gap_report.json.\n"
        OUT.write_text(text, encoding="utf-8")
        return text
    findings = json.loads(GAP.read_text(encoding="utf-8"))
    chunks = ["# Group Policy Recommendations", "", "Generated from gap_report.json FAIL items.", ""]
    for row in findings:
        if row.get("status") != "FAIL":
            continue
        rid = row["rule_id"]
        gpo, val, iso = FAIL_MAP.get(rid, (
            "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options",
            "Review related security option for this control",
            f"{rid} — Align Windows hardening to the failed ISO-aligned check.",
        ))
        chunks += [
            "## Finding",
            f"- **Rule:** {rid}",
            f"- **Description:** {row.get('description','')}",
            f"- **Evidence:** {row.get('evidence','')}",
            "",
            "## Recommended GPO Path",
            gpo,
            "",
            "## Recommended Value",
            val,
            "",
            "## Rationale (ISO 27001 control reference)",
            iso,
            "",
            "---",
            "",
        ]
    if len(chunks) < 6:
        chunks.append("No FAIL findings; no GPO changes required by this engine.")
    text = "\n".join(chunks)
    OUT.write_text(text, encoding="utf-8")
    return text
