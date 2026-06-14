"""
Findings report generator — produces ranked, formatted risk reports.
Supports: terminal table, full assessment narrative, CSV export.
"""

import csv
import sys
from datetime import datetime
from typing import List, Optional

from scoring import Risk, level_color, RISK_LEVELS, LEVEL_ORDER
from heatmap import render_heatmap, render_summary_table, _cell_color, _level_to_score


# ── Column widths for the table ──────────────────────────────────────────────
COL_WIDTHS = [6, 14, 10, 22, 6, 6, 8, 8, 6]
COL_HEADERS = ["ID", "Asset", "Category", "Threat", "L", "I", "Inh.", "Res.", "Ctrl%"]
SEPARATOR = "─" * (sum(COL_WIDTHS) + len(COL_WIDTHS) - 1 + 2)


def _fmt_risk(r: Risk) -> List[str]:
    emoji = level_color(r.inherent_level, use_emoji=True)
    return [
        r.id,
        r.asset[:14],
        r.category[:10],
        r.threat[:22],
        str(r.likelihood),
        str(r.impact),
        f"{r.inherent_risk}",
        f"{r.residual_risk}",
        f"{r.control_effectiveness_pct}%" if r.control else "—",
    ]


def _pad(s: str, w: int, right: bool = False) -> str:
    s = str(s)
    if right:
        return s.rjust(w)
    return s.ljust(w)


def _row_color(r: Risk) -> str:
    color_map = {
        "Critical": "\033[91m",
        "High":     "\033[95m",
        "Medium":   "\033[33m",
        "Low":      "\033[92m",
        "Minimal":  "\033[37m",
    }
    return color_map.get(r.inherent_level, "")


RESET = "\033[0m"
BOLD  = "\033[1m"


def render_findings_table(risks: List[Risk], show_controls: bool = True) -> str:
    """Sort risks by inherent risk descending, print a terminal table."""
    if not risks:
        return "No risks to display."

    # Sort: Critical → Minimal, then by inherent score
    priority = {l: i for i, l in enumerate(LEVEL_ORDER)}
    sorted_risks = sorted(
        risks,
        key=lambda r: (priority.get(r.inherent_level, 99), -r.inherent_risk)
    )

    lines = []
    # Header
    header_cells = [_pad(h, w) for h, w in zip(COL_HEADERS, COL_WIDTHS)]
    lines.append(f"{BOLD}{' '.join(header_cells)}{RESET}")
    lines.append(SEPARATOR)

    for r in sorted_risks:
        cells = _fmt_risk(r)
        color = _row_color(r)
        styled = [f"{color}{_pad(cells[i], COL_WIDTHS[i])}{RESET}" for i in range(len(cells))]
        lines.append(" ".join(styled))

        # Sub-row: control detail
        if show_controls and r.control:
            ctrl_detail = f"   └─ Control: {r.control.name} ({r.control_effectiveness_pct}% effective)"
            lines.append(f"\033[2m{ctrl_detail}{RESET}")

    return "\n".join(lines)


def render_assessment_report(
    risks: List[Risk],
    org_name: str = "Sample Organization",
    assessor: str = "Analyst",
    scope: str = "All IT Assets",
) -> str:
    """Full multi-section assessment report, ready for a stakeholder deck."""
    total = len(risks)
    open_risks = [r for r in risks if r.status == "Open"]
    uncontrolled = [r for r in risks if r.control is None]

    # Count by level
    from collections import Counter
    by_level = Counter(r.inherent_level for r in risks)
    critical_count = by_level.get("Critical", 0)
    high_count = by_level.get("High", 0)
    medium_count = by_level.get("Medium", 0)

    lines = []
    width = 78

    def section(title: str):
        lines.append("")
        lines.append(f"{BOLD}{'═' * width}{RESET}")
        lines.append(f"{BOLD}  {title}{RESET}")
        lines.append(f"{'═' * width}")

    def sub(title: str):
        lines.append(f"{BOLD}■ {title}{RESET}")

    # ── Cover ────────────────────────────────────────────────────────────────
    lines.append("")
    lines.append(f"{BOLD}╔{'═' * width}╗".center(width + 4))
    lines.append(f"║{' ' * width}║".center(width + 4))
    lines.append(f"║  IT RISK ASSESSMENT REPORT".ljust(width + 3) + "║")
    lines.append(f"║  {org_name}".ljust(width + 3) + "║")
    lines.append(f"║{' ' * width}║".center(width + 4))
    lines.append(f"║  Assessed by : {assessor}".ljust(width + 3) + "║")
    lines.append(f"║  Scope       : {scope}".ljust(width + width + 3) + "║")
    lines.append(f"║  Date        : {datetime.now().strftime('%Y-%m-%d')}".ljust(width + 3) + "║")
    lines.append(f"║{' ' * width}║".center(width + 4))
    lines.append(f"╚{'═' * width}╝".center(width + 4))

    # ── Executive Summary ────────────────────────────────────────────────────
    section("EXECUTIVE SUMMARY")
    lines.append(
        f"  This assessment identifies **{total} risks** across the defined scope. "
        f"**{critical_count}** are Critical, **{high_count}** are High, and "
        f"**{medium_count}** are Medium priority."
    )
    lines.append("")
    lines.append(
        f"  **{len(uncontrolled)} risks** have no mitigating control assigned and "
        f"represent the highest priority for remediation. "
        f"**{len([r for r in risks if r.residual_risk >= 10])}** risks retain a High or Critical "
        f"residual rating after controls — requiring executive attention."
    )

    # ── Risk Heat Map ───────────────────────────────────────────────────────
    section("RISK HEAT MAP")
    lines.append(render_heatmap(risks, title="ENTERPRISE RISK HEAT MAP"))

    # ── Detailed Findings ────────────────────────────────────────────────────
    section("DETAILED FINDINGS")
    lines.append(render_findings_table(risks, show_controls=True))

    # ── Portfolio Summary ────────────────────────────────────────────────────
    lines.append(render_summary_table(risks))

    # ── Remediation Priorities ────────────────────────────────────────────────
    section("REMEDIATION PRIORITIES")
    open_sorted = sorted(
        [r for r in risks if r.status == "Open"],
        key=lambda r: (LEVEL_ORDER.index(r.inherent_level) if r.inherent_level in LEVEL_ORDER else 99, -r.inherent_risk)
    )
    for i, r in enumerate(open_sorted[:10], 1):
        color = _cell_color(r.inherent_risk)
        lines.append(
            f"  {i:>2}. {color}{r.id}: {r.threat}{RESET}"
            f"\n      Asset: {r.asset} | Inherent: {r.inherent_risk} | "
            f"Residual: {r.residual_risk}"
        )
        if r.control:
            lines.append(f"      Control gap: {r.control.name} — {r.control.effectiveness * 100:.0f}% effective")
        else:
            lines.append(f"      Control gap: None assigned — immediate action required")
        lines.append("")

    # ── Risk Acceptance Table ─────────────────────────────────────────────────
    section("UNCONTROLLED RISKS REQUIRING RISK ACCEPTANCE")
    if uncontrolled:
        for r in uncontrolled:
            lines.append(
                f"  • {r.id} | {r.asset} | {r.threat} | "
                f"Score: {r.inherent_risk} ({r.inherent_level}) — "
                f"Owner: {r.owner or 'Unassigned'}"
            )
    else:
        lines.append("  All identified risks have at least one control assigned.")

    # ── Footer ───────────────────────────────────────────────────────────────
    section("ASSESSMENT DETAILS")
    lines.append(f"  Framework   : ISO 31000 / NIST CSF Risk Management")
    lines.append(f"  Methodology : Likelihood × Impact = Inherent Risk")
    lines.append(f"  Controls    : Residual Risk = Inherent Risk × (1 − Control Effectiveness)")
    lines.append(f"  Scored by   : {assessor}")
    lines.append(f"  Date        : {datetime.now().strftime('%Y-%m-%d %H:%M')}")

    return "\n".join(lines)


def export_csv(risks: List[Risk], filepath: str) -> None:
    """Export risks to CSV for use in GRC tools or Excel."""
    fieldnames = [
        "ID", "Asset", "Category", "Threat", "Likelihood", "Impact",
        "Inherent Risk", "Inherent Level", "Control", "Control Effectiveness %",
        "Residual Risk", "Residual Level", "Risk Reduction", "Owner", "Status", "Notes"
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in risks:
            writer.writerow({
                "ID": r.id,
                "Asset": r.asset,
                "Category": r.category,
                "Threat": r.threat,
                "Likelihood": r.likelihood,
                "Impact": r.impact,
                "Inherent Risk": r.inherent_risk,
                "Inherent Level": r.inherent_level,
                "Control": r.control.name if r.control else "",
                "Control Effectiveness %": r.control_effectiveness_pct if r.control else 0,
                "Residual Risk": r.residual_risk,
                "Residual Level": r.residual_level,
                "Risk Reduction": r.risk_reduction,
                "Owner": r.owner,
                "Status": r.status,
                "Notes": r.notes,
            })
    print(f"✓ Exported {len(risks)} risks to {filepath}")