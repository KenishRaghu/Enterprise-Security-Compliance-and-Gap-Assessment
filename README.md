# Enterprise Security Compliance and Gap Assessment

## What it is

This is a local Python utility that audits a single machine against a small ISO 27001–aligned control baseline, collects hardware and software inventory, turns failed checks into Windows Group Policy–style recommendations, and plots synthetic SIEM alert trends for practice triage. Everything runs offline with open-source libraries and writes artifacts under `output/`.

## Why I built it

I wanted to rehearse the end-to-end flow a junior GRC or detection engineer follows: pull configuration and inventory, normalize it into a gap report, translate gaps into hardening actions, then relate alert volume back to prioritization. Keeping it on a laptop with no cloud dependencies makes the moving parts easy to read and change.

## How it works

- `inventory` → audit-style `output/inventory.csv` plus structured `output/inventory.json` with a versioned header.
- `scan` → reads `data/compliance_rules.json`, evaluates controls with `psutil` and `subprocess`, emits `output/gap_report.json` and `output/gap_report.txt`.
- `recommend` → ingests `gap_report.json`, maps each **FAIL** through a static dict to GPO-style guidance in `output/gpo_recommendations.md`.
- `dashboard` → parses `data/sample_siem_alerts.csv` with pandas, renders `output/siem_dashboard.png` (four matplotlib panels), and ranks assets in `output/remediation_priority.csv` using severity weights (HIGH=5, MEDIUM=3, LOW=1).

## How to run

git clone <repo>
cd Enterprise-Security-Compliance-and-Gap-Assessment
./setup.sh
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python main.py all

- `inventory` — Collect CPU, memory, disks, MACs, OS, and an installed-software sample into CSV/JSON.
- `scan` — Evaluate the bundled ISO 27001–aligned rules and write gap reports.
- `recommend` — Emit Group Policy recommendation markdown from failed checks.
- `dashboard` — Build the SIEM trend PNG and remediation priority CSV.
- `all` — Run the four stages in order and print a short terminal summary.

## Output files

- `inventory.json` — Header metadata plus nested hardware/software inventory.
- `inventory.csv` — Long-form rows (section, attribute, value) suitable for audit appendices.
- `gap_report.json` — Machine-readable list of rule results with evidence strings.
- `gap_report.txt` — Human-readable gap narrative for the same run.
- `gpo_recommendations.md` — Per-finding GPO path, value, and ISO control rationale.
- `siem_dashboard.png` — Matplotlib figure with daily volume, severity bars, top IPs, and alert types.
- `remediation_priority.csv` — Assets ranked by summed weighted severity from the sample alerts.

## Tech stack

Python 3.11, psutil, pandas, matplotlib.
