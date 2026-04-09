"""Tests for ACL time-based conditions."""

from datetime import datetime, time

from homeassistant.auth.acl.conditions import (
    TimeWindowCondition,
    evaluate_conditions,
)


def test_time_window_weekday_match() -> None:
    """Test time window matches on correct weekday."""
    condition = TimeWindowCondition(
        days=["mon", "tue", "wed", "thu", "fri"],
        after=time(9, 0),
        before=time(17, 0),
    )
    # Monday at 10:00
    now = datetime(2026, 4, 6, 10, 0)  # Monday
    assert condition.evaluate(now) is True


def test_time_window_weekday_no_match() -> None:
    """Test time window doesn't match on wrong weekday."""
    condition = TimeWindowCondition(
        days=["mon", "tue", "wed", "thu", "fri"],
        after=time(9, 0),
        before=time(17, 0),
    )
    # Saturday at 10:00
    now = datetime(2026, 4, 11, 10, 0)  # Saturday
    assert condition.evaluate(now) is False


def test_time_window_time_before_range() -> None:
    """Test time window doesn't match before the time range."""
    condition = TimeWindowCondition(
        days=["mon"],
        after=time(9, 0),
        before=time(17, 0),
    )
    # Monday at 8:00
    now = datetime(2026, 4, 6, 8, 0)
    assert condition.evaluate(now) is False


def test_time_window_time_after_range() -> None:
    """Test time window doesn't match after the time range."""
    condition = TimeWindowCondition(
        days=["mon"],
        after=time(9, 0),
        before=time(17, 0),
    )
    # Monday at 18:00
    now = datetime(2026, 4, 6, 18, 0)
    assert condition.evaluate(now) is False


def test_time_window_boundary_start() -> None:
    """Test time window matches at the start boundary."""
    condition = TimeWindowCondition(
        days=["mon"],
        after=time(9, 0),
        before=time(17, 0),
    )
    now = datetime(2026, 4, 6, 9, 0)
    assert condition.evaluate(now) is True


def test_time_window_boundary_end() -> None:
    """Test time window matches at the end boundary."""
    condition = TimeWindowCondition(
        days=["mon"],
        after=time(9, 0),
        before=time(17, 0),
    )
    now = datetime(2026, 4, 6, 17, 0)
    assert condition.evaluate(now) is True


def test_time_window_overnight() -> None:
    """Test overnight time window (e.g., 22:00 to 06:00)."""
    condition = TimeWindowCondition(
        days=["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
        after=time(22, 0),
        before=time(6, 0),
    )
    # 23:00 - should match
    now = datetime(2026, 4, 6, 23, 0)
    assert condition.evaluate(now) is True

    # 03:00 - should match
    now = datetime(2026, 4, 6, 3, 0)
    assert condition.evaluate(now) is True

    # 12:00 - should not match
    now = datetime(2026, 4, 6, 12, 0)
    assert condition.evaluate(now) is False


def test_time_window_weekend_only() -> None:
    """Test weekend-only time window."""
    condition = TimeWindowCondition(
        days=["sat", "sun"],
        after=time(0, 0),
        before=time(23, 59),
    )
    # Saturday
    now = datetime(2026, 4, 11, 12, 0)
    assert condition.evaluate(now) is True

    # Monday
    now = datetime(2026, 4, 6, 12, 0)
    assert condition.evaluate(now) is False


def test_time_window_serialization() -> None:
    """Test TimeWindowCondition to_dict and from_dict."""
    condition = TimeWindowCondition(
        days=["mon", "wed", "fri"],
        after=time(9, 0),
        before=time(17, 30),
    )
    data = condition.to_dict()
    assert data["type"] == "time_window"
    assert data["days"] == ["mon", "wed", "fri"]
    assert data["after"] == "09:00:00"
    assert data["before"] == "17:30:00"

    restored = TimeWindowCondition.from_dict(data)
    assert restored.days == condition.days
    assert restored.after == condition.after
    assert restored.before == condition.before


def test_evaluate_conditions_none() -> None:
    """Test that None conditions always passes."""
    assert evaluate_conditions(None) is True


def test_evaluate_conditions_empty() -> None:
    """Test that empty conditions always passes."""
    assert evaluate_conditions({}) is True


def test_evaluate_conditions_time_window() -> None:
    """Test evaluating a time window condition dict."""
    conditions = {
        "type": "time_window",
        "days": ["mon"],
        "after": "09:00:00",
        "before": "17:00:00",
    }
    # Monday at 12:00
    now = datetime(2026, 4, 6, 12, 0)
    assert evaluate_conditions(conditions, now) is True

    # Monday at 20:00
    now = datetime(2026, 4, 6, 20, 0)
    assert evaluate_conditions(conditions, now) is False


def test_evaluate_conditions_unknown_type() -> None:
    """Test that unknown condition types fail open."""
    conditions = {"type": "unknown_condition"}
    assert evaluate_conditions(conditions) is True
