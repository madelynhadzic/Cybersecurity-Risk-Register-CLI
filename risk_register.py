#!/usr/bin/env python3
"""
Risk Register CLI — IT Risk Assessment Tool
Implements ISO 31000 risk scoring: Likelihood × Impact = Inherent Risk
Residual Risk = Inherent Risk × (1 − Control Effectiveness)

Usage:
    python risk_register.py                          # runs with sample data
    python risk_register.py --file my_risks.csv      # loads custom CSV
    python risk_register.py --export my_risks.csv    # export sample to CSV
    python risk_register.py --add                    # interactive risk entry
"""

import argparse
import csv
import sys
from pathlib import Path
from typing import List, Optional

from scoring import Risk, Control, RISK_LEVELS, LEVEL_ORDER, level_color
from heatmap import render_heatmap, render_summary_table
from report import render_findings_table, render_assessment_report, export_csv


# ── CSV parser ───────────────────────────────────────────────────────────────

def parse_risks_from_csv(filepath: str) -> List[Risk]:
    """Parse risks from a CSV file."""
    risks = []
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            control = None
            if row.get("Control Name") and row.get("Control Effectiveness"):
                try:
                    control = Control(
                        name=row["Control Name"],
                        effectiveness=float(row["Control Effectiveness"]),
                    )
                except ValueError:
                    control = None

            try:
                risk = Risk(
                    id=row["ID"],
                    asset=row["Asset"],
                    category=row.get("Category", "Uncategorized"),
                    threat=row["Threat"],
                    likelihood=int(row["Likelihood"]),
                    impact=int(row["Impact"]),
                    control=control,
                    owner=row.get("Owner", ""),
                    status=row.get("Status", "Open"),
                    notes=row.get("Notes", ""),
                )
                risks.append(risk)
            except (KeyError, ValueError) as e:
                print(f"⚠  Skipping row {row}: {e}", file=sys.stderr)
    return risks


def write_risks_to_csv(risks: List[Risk], filepath: str) -> None:
    """Export risks back to CSV."""
    export_csv(risks, filepath)


# ── Built-in sample data ──────────────────────────────────────────────────────

def sample_risks() -> List[Risk]:
    """Realistic enterprise IT risk scenarios mapped to NIST CSF / ISO 27001."""
    return [
        # ── Critical ──────────────────────────────────────────────────────
        Risk(
            id="R-001",
            asset="AWS S3 Production Bucket",
            category="Data Protection",
            threat="Unrestricted S3 bucket policy exposes PII to public internet",
            likelihood=5, impact=4,
            control=Control("S3 Block Public Access + bucket policy review", 0.95),
            owner="Cloud Security Lead",
            notes="Identified during quarterly cloud posture review",
        ),
        Risk(
            id="R-002",
            asset="Active Directory Domain",
            category="Identity & Access",
            threat="Privileged accounts lack MFA; lateral movement risk after credential theft",
            likelihood=4, impact=5,
            control=Control("Azure AD Conditional Access MFA enforcement", 0.80),
            owner="IT Security Manager",
            notes="Residual elevated due to legacy service accounts",
        ),
        Risk(
            id="R-003",
            asset="Production Database Cluster",
            category="Vulnerability Management",
            threat="Critical unpatched CVE in database engine; active exploit in wild",
            likelihood=3, impact=5,
            control=Control("Network segmentation + IDS monitoring", 0.60),
            owner="DBA / Platform Engineering",
            notes="Patch scheduled but blocked by uptime SLA — risk accepted pending window",
        ),
        # ── High ──────────────────────────────────────────────────────────
        Risk(
            id="R-004",
            asset="Vendor SaaS Platform (HRIS)",
            category="Third-Party Risk",
            threat="HRIS vendor suffers data breach; employee PII exfiltrated",
            likelihood=3, impact=4,
            control=Control("Vendor SOC 2 Type II + DPA in place", 0.85),
            owner="Procurement / GRC",
            notes="Sub-processor risk not fully assessed",
        ),
        Risk(
            id="R-005",
            asset="CI/CD Pipeline",
            category="Secure Development",
            threat="Compromised build agent injects malicious code into production release",
            likelihood=3, impact=4,
            control=Control("Pipeline signing + artifact verification", 0.90),
            owner="DevOps Lead",
            notes="Supply chain risk — build infrastructure not fully hardened",
        ),
        Risk(
            id="R-006",
            asset="Remote Desktop / VPN",
            category="Identity & Access",
            threat="Phishing attack compromises VPN credentials; attacker pivots to internal",
            likelihood=4, impact=3,
            control=Control("MFA + endpoint detection on corporate endpoints", 0.80),
            owner="IT Security",
        ),
        Risk(
            id="R-007",
            asset="Internal Wiki / Confluence",
            category="Information Security",
            threat="Sensitive architecture diagrams and API keys leaked via public share link",
            likelihood=2, impact=4,
            control=Control("DLP rules + quarterly access reviews", 0.70),
            owner="IT Security",
        ),
        # ── Medium ─────────────────────────────────────────────────────────
        Risk(
            id="R-008",
            asset="Laptop Fleet (150 endpoints)",
            category="Endpoint Security",
            threat="Malware infection spreads via unpatched OS vulnerabilities",
            likelihood=3, impact=3,
            control=Control("EDR + auto-patching within 7-day SLA", 0.75),
            owner="IT Operations",
        ),
        Risk(
            id="R-009",
            asset="Email Gateway",
            category="Phishing & Social Engineering",
            threat="Business Email Compromise (BEC) attack — finance tricked into wire transfer",
            likelihood=3, impact=3,
            control=Control("DMARC + banner warnings + BEC training", 0.65),
            owner="IT Security / Finance",
        ),
        Risk(
            id="R-010",
            asset="Backup Infrastructure",
            category="Business Continuity",
            threat="Ransomware encrypts primary and backup systems simultaneously",
            likelihood=2, impact=4,
            control=Control("Immutable backups (WORM) + offline copy", 0.95),
            owner="IT Operations",
        ),
        # ── Low / Minimal ──────────────────────────────────────────────────
        Risk(
            id="R-011",
            asset="Internal DNS Server",
            category="Network Security",
            threat="DNS cache poisoning redirects users to phishing site",
            likelihood=2, impact=2,
            control=Control("DNSSEC + recursive resolver hardening", 0.90),
            owner="Network Engineering",
        ),
        Risk(
            id="R-012",
            asset="Physical Office Access",
            category="Physical Security",
            threat="Tailgating into server room by unauthorized personnel",
            likelihood=1, impact=3,
            control=Control("Badge access logging + mantrap entry", 0.85),
            owner="Facilities",
        ),
        # ── Uncontrolled (no control — critical demo) ────────────────────
        Risk(
            id="R-013",
            asset="Legacy ERP System",
            category="End-of-Life Systems",
            threat="End-of-life ERP has no vendor patches; exploitation leads to data loss",
            likelihood=2, impact=5,
            owner="IT Director",
            status="Open",
            notes="Migration project in progress — 6-month timeline. Risk acceptance pending CIO sign-off.",
        ),
        Risk(
            id="R-014",
            asset="Developer Workstations",
            category="Secure Development",
            threat="Developer installs unvetted open-source package with malicious code",
            likelihood=3, impact=4,
            owner="AppSec",
            notes="No SCA tooling on developer workstations yet. Tool procurement pending Q3 budget.",
        ),
    ]


# ── Interactive risk entry ────────────────────────────────────────────────────

def interactive_add() -> Risk:
    print("\n📝  Add a New Risk\n" + "─" * 40)
    risk_id = input("Risk ID (e.g. R-015): ").strip() or f"R-{len(sample_risks()) + 1:03d}"
    asset   = input("Asset name: ").strip()
    category = input("Category: ").strip() or "General"
    threat  = input("Threat description: ").strip()
    likelihood = _get_int("Likelihood (1-5, where 5=most likely): ", 1, 5)
    impact  = _get_int("Impact (1-5, where 5=most severe): ", 1, 5)
    has_control = input("Add a control? (y/N): ").strip().lower() == "y"
    control = None
    if has_control:
        ctrl_name = input("  Control name: ").strip()
        ctrl_eff  = _get_float("  Effectiveness (0.0–1.0, e.g. 0.75): ", 0.0, 1.0)
        control = Control(ctrl_name, ctrl_eff)
    owner = input("Risk owner: ").strip()
    notes = input("Notes: ").strip()
    return Risk(
        id=risk_id, asset=asset, category=category, threat=threat,
        likelihood=likelihood, impact=impact, control=control,
        owner=owner, notes=notes,
    )


def _get_int(prompt: str, lo: int, hi: int) -> int:
    while True:
        try:
            v = int(input(prompt))
            if lo <= v <= hi:
                return v
            print(f"  Must be between {lo} and {hi}")
        except ValueError:
            print("  Enter a number.")


def _get_float(prompt: str, lo: float, hi: float) -> float:
    while True:
        try:
            v = float(input(prompt))
            if lo <= v <= hi:
                return v
            print(f"  Must be between {lo} and {hi}")
        except ValueError:
            print("  Enter a number.")


# ── Main CLI ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Risk Register CLI — IT Risk Assessment Tool (ISO 31000)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python risk_register.py                              # run with sample data
  python risk_register.py --file risks.csv               # load your own CSV
  python risk_register.py --export my_export.csv         # export sample to CSV
  python risk_register.py --add                          # add risk interactively
  python risk_register.py --heatmap                     # heat map only
  python risk_register.py --findings                    # findings table only
  python risk_register.py --report                       # full assessment report
  python risk_register.py --file risks.csv --report     # report from CSV
        """
    )
    parser.add_argument("--file", "-f", help="Load risks from CSV file")
    parser.add_argument("--export", "-e", help="Export risks to CSV")
    parser.add_argument("--add", "-a", action="store_true", help="Add a new risk interactively")
    parser.add_argument("--heatmap", action="store_true", help="Show heat map only")
    parser.add_argument("--findings", action="store_true", help="Show findings table only")
    parser.add_argument("--report", "-r", action="store_true", help="Show full assessment report")
    parser.add_argument("--org", default="Acme Corp IT", help="Organization name for report")
    parser.add_argument("--assessor", default="Risk Analyst", help="Assessor name for report")
    parser.add_argument("--scope", default="All IT Assets", help="Scope description")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")

    args = parser.parse_args()

    # Load risks
    if args.file:
        risks = parse_risks_from_csv(args.file)
        if not risks:
            print("⚠  No risks loaded. Check your CSV format.", file=sys.stderr)
            sys.exit(1)
    else:
        risks = sample_risks()

    # Export
    if args.export:
        write_risks_to_csv(risks, args.export)
        return

    # Add risk
    if args.add:
        new_risk = interactive_add()
        risks.append(new_risk)
        print(f"\n✅ Added {new_risk.id}: {new_risk.threat}")
        print(f"   Inherent risk: {new_risk.inherent_risk} ({new_risk.inherent_level})")
        if new_risk.control:
            print(f"   Residual risk: {new_risk.residual_risk} ({new_risk.residual_level})")

    # Decide what to show
    show_heatmap  = args.heatmap
    show_findings = args.findings
    show_report   = args.report

    if not (show_heatmap or show_findings or show_report):
        # Default: show everything
        show_heatmap = show_findings = show_report = True

    if show_report:
        print(render_assessment_report(
            risks,
            org_name=args.org,
            assessor=args.assessor,
            scope=args.scope,
        ))
    else:
        if show_heatmap:
            print(render_heatmap(risks, title="RISK HEAT MAP"))
            print(render_summary_table(risks))
        if show_findings:
            if show_heatmap:
                print("")
            print(render_findings_table(risks))


if __name__ == "__main__":
    main()