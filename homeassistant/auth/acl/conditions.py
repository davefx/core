"""Time-based conditions for ACL rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time
from typing import Any

from homeassistant.util import dt as dt_util

WEEKDAY_MAP = {
    "mon": 0,
    "tue": 1,
    "wed": 2,
    "thu": 3,
    "fri": 4,
    "sat": 5,
    "sun": 6,
}


@dataclass(slots=True)
class TimeWindowCondition:
    """A time window condition for ACL rules.

    Specifies days of the week and a time range during which
    the rule is active.
    """

    days: list[str]  # e.g., ["mon", "tue", "wed", "thu", "fri"]
    after: time  # e.g., time(9, 0)
    before: time  # e.g., time(17, 0)

    def evaluate(self, now: datetime | None = None) -> bool:
        """Check if the current time falls within this window.

        Returns True if the condition is met (rule should be active).
        """
        if now is None:
            now = dt_util.now()

        # Check day of week
        current_weekday = now.weekday()
        day_match = any(
            WEEKDAY_MAP.get(day.lower()) == current_weekday for day in self.days
        )
        if not day_match:
            return False

        # Check time range
        current_time = now.time()

        if self.after <= self.before:
            # Normal range (e.g., 09:00 to 17:00)
            return self.after <= current_time <= self.before
        # Overnight range (e.g., 22:00 to 06:00)
        return current_time >= self.after or current_time <= self.before

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "type": "time_window",
            "days": self.days,
            "after": self.after.isoformat(),
            "before": self.before.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TimeWindowCondition:
        """Deserialize from dict."""
        return cls(
            days=data["days"],
            after=time.fromisoformat(data["after"]),
            before=time.fromisoformat(data["before"]),
        )


def evaluate_conditions(conditions: dict[str, Any] | None, now: datetime | None = None) -> bool:
    """Evaluate a set of conditions.

    Returns True if all conditions are met, or if no conditions exist.
    """
    if not conditions:
        return True

    condition_type = conditions.get("type")

    if condition_type == "time_window":
        condition = TimeWindowCondition.from_dict(conditions)
        return condition.evaluate(now)

    # Unknown condition type — fail open (allow)
    return True
