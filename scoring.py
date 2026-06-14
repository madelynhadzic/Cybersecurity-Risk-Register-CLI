"""
Risk scoring logic — implements ISO 31000 risk assessment methodology.

Inherent Risk  = Likelihood (1-5) × Impact (1-5)
Control Factor = 1.0 - Control Effectiveness (0.0-1.0)
Residual Risk = Inherent Risk × Control Factor
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Control:
    name: str
    effectiveness: float  # 0.0 (no effect) → 1.0 (fully mitigates)


@dataclass
class Risk:
    id: str
    asset: str
    category: str
    threat: str
    likelihood: int  # 1-5
    impact: int      # 1-5
    control: Optional[Control] = None
    owner: str = ""
    status: str = "Open"
    notes: str = ""

    @property
    def inherent_risk(self) -> int:
        return self.likelihood * self.impact

    @property
    def residual_risk(self) -> int:
        if self.control is None:
            return self.inherent_risk
        cf = 1.0 - self.control.effectiveness
        return round(self.inherent_risk * cf)

    @property
    def inherent_level(self) -> str:
        return _score_to_level(self.inherent_risk)

    @property
    def residual_level(self) -> str:
        return _score_to_level(self.residual_risk)

    @property
    def risk_reduction(self) -> int:
        return self.inherent_risk - self.residual_risk

    @property
    def control_effectiveness_pct(self) -> int:
        if self.control is None:
            return 0
        return int(self.control.effectiveness * 100)


def _score_to_level(score: int) -> str:
    if score >= 16:
        return "Critical"
    elif score >= 10:
        return "High"
    elif score >= 6:
        return "Medium"
    elif score >= 3:
        return "Low"
    else:
        return "Minimal"


RISK_LEVELS = {
    "Critical":  ("🔴", "\033[91m"),  # red
    "High":      ("🟠", "\033[93m"),  # orange/yellow
    "Medium":    ("🟡", "\033[33m"),  # yellow
    "Low":       ("🟢", "\033[92m"),  # green
    "Minimal":   ("⚪", "\033[37m"),  # white
}
LEVEL_ORDER  = ["Critical", "High", "Medium", "Low", "Minimal"]


def level_color(level: str, use_emoji: bool = True) -> str:
    if use_emoji:
        return RISK_LEVELS.get(level, ("⚪", ""))[0]
    color = RISK_LEVELS.get(level, ("", ""))[1]
    return f"{color}{level}\033[0m"