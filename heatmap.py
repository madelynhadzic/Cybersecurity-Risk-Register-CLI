"""
ASCII risk heat map generator.

Grid: Likelihood (Y-axis, 5→1 top-down) × Impact (X-axis, 1→5 left-right)
Cells show risk IDs or dots. Color-coded via ANSI.
"""

from typing import List
from scoring import Risk, level_color, RISK_LEVELS

# ANSI color codes
C_CRIT  = "\033[91m"   # red
C_HIGH  = "\033[95m"   # magenta / bright red
C_MED   = "\033[33m"   # yellow
C_LOW   = "\033[92m"   # green
C_MIN   = "\033[37m"   # grey
C_RESET = "\033[0m"
C_BOLD  = "\033[1m"
C_DIM   = "\033[2m"


def _cell_color(inherent: int) -> str:
    if inherent >= 16:
        return C_CRIT
    elif inherent >= 10:
        return C_HIGH
    elif inherent >= 6:
        return C_MED
    elif inherent >= 3:
        return C_LOW
    return C_MIN


def _cell_label(inherent: int) -> str:
    if inherent >= 16:
        return "CRIT"
    elif inherent >= 10:
        return "HIGH"
    elif inherent >= 6:
        return "MED "
    elif inherent >= 3:
        return "LOW "
    return "MIN "


def build_grid(risks: List[Risk]) -> dict:
    """Return { (likelihood, impact): [Risk, ...] }."""
    grid = {}
    for r in risks:
        grid.setdefault((r.likelihood, r.impact), []).append(r)
    return grid


def render_heatmap(risks: List[Risk], title: str = "RISK HEAT MAP") -> str:
    grid = build_grid(risks)

    lines = []
    width = 72

    # ── Header ──────────────────────────────────────────────────────────────
    lines.append(C_BOLD + f"╔{'═' * width}╗".center(width + 8))
    lines.append(f"║  {title.center(width)}  ║")
    lines.append(f"╠{'═' * width}╣".center(width + 8))
    lines.append(f"║  Likelihood (Y) vs Impact (X)  |  Score = Likelihood × Impact  ║")
    lines.append(f"╚{'═' * width}╝".center(width + 8) + C_RESET)

    # ── Column headers ───────────────────────────────────────────────────────
    header = f"{'':^8}" + "".join(
        f"{C_BOLD}IMPACT {i}{C_RESET:^8}" for i in range(1, 6)
    )
    lines.append(header)
    lines.append(f"{'':─<{8 + 9*5}}")

    # ── Rows (likelihood 5 → 1) ─────────────────────────────────────────────
    for likelihood in range(5, 0, -1):
        row_cells = []
        for impact in range(1, 6):
            cell_risks = grid.get((likelihood, impact), [])
            score = likelihood * impact
            label = _cell_label(score)
            color = _cell_color(score)
            count = len(cell_risks)

            if count == 0:
                cell = f"{C_DIM}{'·':^8}{C_RESET}"
            elif count == 1:
                # Show risk ID in the cell
                rid = cell_risks[0].id
                cell = f"{color}{C_BOLD}{rid:^8}{C_RESET}"
            else:
                cell = f"{color}{C_BOLD}[{count}]{'─':<5}{C_RESET}"

            row_cells.append(cell)

        label_color = _cell_color(likelihood * 3)  # midpoint impact
        row = f"{label_color}{C_BOLD}LIK {likelihood}{C_RESET:^8}" + "".join(row_cells)
        lines.append(row)
        lines.append(f"{'':─<{8 + 9*5}}")

    # ── Legend ──────────────────────────────────────────────────────────────
    lines.append("")
    lines.append(f"{C_BOLD}RISK MATRIX LEGEND:{C_RESET}")
    for level, (emoji, _) in RISK_LEVELS.items():
        color = _cell_color(_level_to_score(level))
        lines.append(f"  {color}{level:10}{C_RESET}  score {_level_to_score(level):>2}  {emoji}")
    lines.append("")
    lines.append(f"{C_DIM}  Score = Likelihood (1-5) × Impact (1-5){C_RESET}")
    lines.append(f"{C_DIM}  Residual = Inherent × (1 - Control Effectiveness){C_RESET}")

    return "\n".join(lines)


def _level_to_score(level: str) -> int:
    mapping = {"Critical": 20, "High": 15, "Medium": 10, "Low": 5, "Minimal": 1}
    return mapping.get(level, 1)


def render_summary_table(risks: List[Risk]) -> str:
    """High-level portfolio summary by risk level."""
    from collections import Counter
    level_counts = Counter(r.inherent_level for r in risks)

    lines = []
    lines.append(f"\n{C_BOLD}╔════════════════════════════════════════╗")
    lines.append(f"║          RISK PORTFOLIO SUMMARY         ║")
    lines.append(f"╠════════════════════════════════════════╣{C_RESET}")
    for level in ["Critical", "High", "Medium", "Low", "Minimal"]:
        count = level_counts.get(level, 0)
        color = _cell_color(_level_to_score(level))
        bar = "█" * count if count else ""
        lines.append(f"  {color}{level:<12}{C_RESET}  {count:>3}  {bar}")
    lines.append(f"{C_BOLD}╚════════════════════════════════════════╝{C_RESET}")
    return "\n".join(lines)