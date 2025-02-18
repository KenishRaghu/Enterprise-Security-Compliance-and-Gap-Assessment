"""ISO 27001-aligned gap checks: stdlib + psutil + subprocess."""
from __future__ import annotations

import json
import platform
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Tuple

import psutil

ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "data" / "compliance_rules.json"
OUT_DIR = ROOT / "output"
SYS = platform.system


def _sh(cmd: str, t: int = 20) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (subprocess.TimeoutExpired, OSError) as e:
        return -1, str(e)


def _chk_password() -> Tuple[str, str]:
    if SYS() == "Darwin":
        _, o = _sh("pwpolicy -getaccountpolicies 2>/dev/null | head -15")
        if any(x in o for x in ("minChars", "minLength")):
            return "PASS", o[:180] or "pwpolicy"
        return "FAIL", "No pwpolicy min length signal"
    if SYS() == "Linux":
        _, o = _sh("grep '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | head -1")
        v = 0
        if o.strip():
            try:
                v = int(o.split()[-1])
            except ValueError:
                v = 0
        return ("PASS" if v >= 12 else "FAIL"), o.strip() or "login.defs"
    if SYS() == "Windows":
        _, o = _sh("net accounts | findstr /I length")
        return ("PASS" if o.strip() else "FAIL"), o.strip() or "net accounts"
    return "NOT_APPLICABLE", "OS"


def _chk_fw() -> Tuple[str, str]:
    if SYS() == "Darwin":
        _, o = _sh("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null")
        return ("PASS" if "enabled" in o.lower() else "FAIL"), o.strip() or "alf"
    if SYS() == "Linux":
        _, o = _sh("systemctl is-active ufw; systemctl is-active firewalld")
        return ("PASS" if "active" in o else "FAIL"), o.strip()
    if SYS() == "Windows":
        _, o = _sh("netsh advfirewall show allprofiles state | findstr /I ON")
        return ("PASS" if "ON" in o.upper() else "FAIL"), o.strip()
    return "NOT_APPLICABLE", "OS"


def _chk_guest() -> Tuple[str, str]:
    if SYS() == "Darwin":
        rc, o = _sh("defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null")
        return ("PASS" if rc != 0 or o.strip() == "0" else "FAIL"), o.strip() or "guest"
    if SYS() == "Windows":
        _, o = _sh("net user guest")
        return ("FAIL" if "active" in o.lower() and "yes" in o.lower() else "PASS"), o[:120]
    return "NOT_APPLICABLE", "N/A"


def _chk_smb1() -> Tuple[str, str]:
    if SYS() == "Darwin":
        return "PASS", "SMBv1 not default on recent macOS"
    if SYS() == "Linux":
        _, o = _sh("test -f /etc/modprobe.d/disable-smbv1.conf && echo y")
        return ("PASS" if o.strip() == "y" else "FAIL"), o or "modprobe"
    if SYS() == "Windows":
        _, o = _sh('powershell -NoP -C "Get-SmbServerConfiguration|Select EnableSMB1Protocol"')
        return ("PASS" if "False" in o else "FAIL"), o.strip()
    return "NOT_APPLICABLE", "OS"


def _chk_updates() -> Tuple[str, str]:
    if SYS() == "Darwin":
        rc, o = _sh("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null")
        return ("PASS" if rc == 0 and o.strip() == "1" else "FAIL"), o.strip()
    if SYS() == "Linux":
        _, o = _sh("systemctl is-enabled unattended-upgrades 2>/dev/null; systemctl is-enabled dnf-automatic.timer 2>/dev/null")
        return ("PASS" if "enabled" in o else "FAIL"), o.strip()
    if SYS() == "Windows":
        _, o = _sh('powershell -NoP -C "(Get-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU -ea 0).AUOptions"')
        return ("PASS" if o.strip() in ("2", "3", "4") else "FAIL"), o.strip()
    return "NOT_APPLICABLE", "OS"


def _chk_screen() -> Tuple[str, str]:
    if SYS() == "Darwin":
        rc, o = _sh("defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null")
        ok = rc == 0 and o.strip().isdigit() and int(o) <= 900
        return ("PASS" if ok else "FAIL"), o.strip()
    if SYS() == "Windows":
        _, o = _sh('powershell -NoP -C "(Get-ItemProperty HKCU:\\Control Panel\\Desktop).ScreenSaveTimeOut"')
        ok = o.strip().isdigit() and int(o) <= 900
        return ("PASS" if ok else "FAIL"), o.strip()
    return "NOT_APPLICABLE", "Linux session"


def _chk_fde() -> Tuple[str, str]:
    if SYS() == "Darwin":
        _, o = _sh("/usr/sbin/fdesetup status 2>/dev/null")
        return ("PASS" if "FileVault is On" in o else "FAIL"), (o.split("\n")[0] if o else "")
    if SYS() == "Linux":
        _, o = _sh("grep -s '^[^#]' /etc/crypttab 2>/dev/null | head -1")
        return ("PASS" if o.strip() else "FAIL"), o.strip()
    if SYS() == "Windows":
        _, o = _sh('powershell -NoP -C "(Get-BitLockerVolume -MountPoint C: -ea 0).ProtectionStatus"')
        return ("PASS" if "On" in o else "FAIL"), o.strip()
    return "NOT_APPLICABLE", "OS"


def _chk_rdp() -> Tuple[str, str]:
    if SYS() == "Darwin":
        rc, o = _sh("defaults read /Library/Preferences/com.apple.RemoteManagement.plist ARDAgentEnabled 2>/dev/null")
        return ("FAIL" if rc == 0 and o.strip() == "1" else "PASS"), o.strip() or "ard off"
    if SYS() == "Linux":
        _, o = _sh("systemctl is-active xrdp 2>/dev/null")
        return ("FAIL" if o.strip() == "active" else "PASS"), o.strip()
    if SYS() == "Windows":
        _, o = _sh('powershell -NoP -C "(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server).fDenyTSConnections"')
        return ("FAIL" if o.strip() == "0" else "PASS"), o.strip()
    return "NOT_APPLICABLE", "OS"


def _chk_av() -> Tuple[str, str]:
    for p in psutil.process_iter(attrs=["name"]):
        try:
            n = (p.info.get("name") or "").lower()
            if any(x in n for x in ("msmpeng", "mdatp", "sophos", "defender", "clam", "esets")):
                return "PASS", n
        except (psutil.Error, TypeError):
            pass
    if SYS() == "Darwin":
        _, o = _sh("spctl --status 2>/dev/null")
        return ("PASS" if "enabled" in o.lower() else "FAIL"), o.strip()
    if SYS() == "Windows":
        _, o = _sh('powershell -NoP -C "try{(Get-MpComputerStatus).AntivirusEnabled}catch{$false}"')
        return ("PASS" if "True" in o else "FAIL"), o.strip()
    return "FAIL", "no AV signal"


def _chk_audit() -> Tuple[str, str]:
    if SYS() == "Darwin":
        rc, _ = _sh("test -f /etc/asl.conf && echo ok")
        return ("PASS" if rc == 0 else "FAIL"), "asl.conf"
    if SYS() == "Linux":
        _, o = _sh("systemctl is-active auditd 2>/dev/null")
        return ("PASS" if o.strip() == "active" else "FAIL"), o.strip()
    if SYS() == "Windows":
        _, o = _sh("wevtutil gl Security 2>nul | findstr /I enabled")
        return ("PASS" if o.strip() else "FAIL"), o.strip()
    return "NOT_APPLICABLE", "OS"


REG: Dict[str, Callable[[], Tuple[str, str]]] = {
    "password_min_length": _chk_password, "firewall_enabled": _chk_fw, "guest_disabled": _chk_guest,
    "smbv1_disabled": _chk_smb1, "auto_update_enabled": _chk_updates, "screen_lock_timeout": _chk_screen,
    "disk_encryption": _chk_fde, "remote_desktop_exposure": _chk_rdp, "antivirus_running": _chk_av,
    "audit_logging": _chk_audit,
}


def run_scan() -> List[dict]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rules = json.loads(RULES_PATH.read_text(encoding="utf-8"))["rules"]
    out: List[dict] = []
    for r in rules:
        fn = REG.get(r["check_key"])
        if not fn:
            out.append({"rule_id": r["rule_id"], "description": r["description"], "severity": r["severity"], "status": "NOT_APPLICABLE", "evidence": "unimplemented"})
            continue
        st, ev = fn()
        out.append({"rule_id": r["rule_id"], "description": r["description"], "status": st, "severity": r["severity"], "evidence": ev[:500]})
    (OUT_DIR / "gap_report.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    lines = [f"Gap — {platform.node()} — {platform.platform()}", "=" * 50]
    for x in out:
        lines += [f"[{x['status']}] {x['rule_id']} {x['severity']} {x['description']}", f"  {x['evidence']}", ""]
    (OUT_DIR / "gap_report.txt").write_text("\n".join(lines), encoding="utf-8")
    return out
