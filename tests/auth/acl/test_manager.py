"""Tests for ACL manager."""

from unittest.mock import MagicMock, patch

from freezegun.api import FrozenDateTimeFactory
import pytest

from homeassistant.auth.acl import ACLManager
from homeassistant.auth.acl.models import ACLRule, validate_rule_shape

# 2026-04-06 is a Monday.
_TIME_WINDOW = {
    "type": "time_window",
    "days": ["mon"],
    "after": "09:00:00",
    "before": "17:00:00",
}


def test_acl_rule_serialization() -> None:
    """Test ACL rule to_dict and from_dict."""
    rule = ACLRule(
        role_id="test-role",
        category="entities",
        target_type="entity_ids",
        target_id="light.kitchen",
        permission="control",
        effect="deny",
        priority=10,
    )
    data = rule.to_dict()
    assert data["role_id"] == "test-role"
    assert data["category"] == "entities"
    assert data["target_type"] == "entity_ids"
    assert data["target_id"] == "light.kitchen"
    assert data["permission"] == "control"
    assert data["effect"] == "deny"
    assert data["priority"] == 10
    assert data["id"] is not None
    assert data["created_at"] is not None

    restored = ACLRule.from_dict(data)
    assert restored.id == rule.id
    assert restored.role_id == rule.role_id
    assert restored.effect == rule.effect


def test_compile_rules_empty() -> None:
    """Test compiling empty rules produces empty policy."""

    manager = ACLManager.__new__(ACLManager)
    manager._store = MagicMock()
    manager._store.async_get_rules.return_value = []

    policy = manager.compile_rules_to_policy("test-role")
    assert policy == {}


def test_compile_rules_single_allow() -> None:
    """Test compiling a single allow rule."""

    manager = ACLManager.__new__(ACLManager)
    manager._store = MagicMock()
    manager._store.async_get_rules.return_value = [
        ACLRule(
            role_id="test-role",
            category="entities",
            target_type="all",
            target_id=None,
            permission="read",
            effect="allow",
        ),
    ]

    policy = manager.compile_rules_to_policy("test-role")
    assert policy == {"entities": {"all": {"read": True}}}


def test_compile_rules_deny() -> None:
    """Test compiling a deny rule."""

    manager = ACLManager.__new__(ACLManager)
    manager._store = MagicMock()
    manager._store.async_get_rules.return_value = [
        ACLRule(
            role_id="test-role",
            category="entities",
            target_type="entity_ids",
            target_id="alarm_control_panel.main",
            permission="control",
            effect="deny",
        ),
        ACLRule(
            role_id="test-role",
            category="entities",
            target_type="all",
            target_id=None,
            permission="read",
            effect="allow",
        ),
        ACLRule(
            role_id="test-role",
            category="entities",
            target_type="all",
            target_id=None,
            permission="control",
            effect="allow",
        ),
    ]

    policy = manager.compile_rules_to_policy("test-role")
    assert policy == {
        "entities": {
            "entity_ids": {
                "alarm_control_panel.main": {"control": False},
            },
            "all": {"read": True, "control": True},
        }
    }


def test_compile_rules_multiple_categories() -> None:
    """Test compiling rules across multiple categories."""

    manager = ACLManager.__new__(ACLManager)
    manager._store = MagicMock()
    manager._store.async_get_rules.return_value = [
        ACLRule(
            role_id="test-role",
            category="entities",
            target_type="all",
            target_id=None,
            permission="read",
            effect="allow",
        ),
        ACLRule(
            role_id="test-role",
            category="services",
            target_type="service_ids",
            target_id="homeassistant.restart",
            permission="control",
            effect="deny",
        ),
        ACLRule(
            role_id="test-role",
            category="services",
            target_type="all",
            target_id=None,
            permission="control",
            effect="allow",
        ),
    ]

    policy = manager.compile_rules_to_policy("test-role")
    assert policy == {
        "entities": {"all": {"read": True}},
        "services": {
            "service_ids": {"homeassistant.restart": {"control": False}},
            "all": {"control": True},
        },
    }


def test_compile_rules_label_deny() -> None:
    """Test compiling a label-based deny rule."""

    manager = ACLManager.__new__(ACLManager)
    manager._store = MagicMock()
    manager._store.async_get_rules.return_value = [
        ACLRule(
            role_id="test-role",
            category="entities",
            target_type="label_ids",
            target_id="protected",
            permission="control",
            effect="deny",
        ),
        ACLRule(
            role_id="test-role",
            category="entities",
            target_type="label_ids",
            target_id="protected",
            permission="edit",
            effect="deny",
        ),
        ACLRule(
            role_id="test-role",
            category="entities",
            target_type="all",
            target_id=None,
            permission="read",
            effect="allow",
        ),
        ACLRule(
            role_id="test-role",
            category="entities",
            target_type="all",
            target_id=None,
            permission="control",
            effect="allow",
        ),
    ]

    policy = manager.compile_rules_to_policy("test-role")
    assert policy == {
        "entities": {
            "label_ids": {
                "protected": {"control": False, "edit": False},
            },
            "all": {"read": True, "control": True},
        }
    }


def test_compile_rules_time_window(freezer: FrozenDateTimeFactory) -> None:
    """A time-window rule is compiled only while its window is open."""
    manager = ACLManager.__new__(ACLManager)
    manager._store = MagicMock()
    manager._store.async_get_rules.return_value = [
        ACLRule(
            role_id="test-role",
            category="entities",
            target_type="all",
            target_id=None,
            permission="control",
            effect="deny",
            conditions=_TIME_WINDOW,
        ),
    ]

    # Monday 12:00 -> inside the window -> the deny rule is active.
    freezer.move_to("2026-04-06 12:00:00")
    assert manager.compile_rules_to_policy("test-role") == {
        "entities": {"all": {"control": False}}
    }

    # Monday 20:00 -> outside the window -> the rule drops out.
    freezer.move_to("2026-04-06 20:00:00")
    assert manager.compile_rules_to_policy("test-role") == {}


def test_time_tracking_started_only_with_time_window_rules() -> None:
    """The periodic recompile timer runs only when a time-window rule exists."""
    manager = ACLManager.__new__(ACLManager)
    manager.hass = MagicMock()
    manager._store = MagicMock()
    manager._unsub_time = None

    plain_rule = ACLRule(
        role_id="r",
        category="entities",
        target_type="all",
        target_id=None,
        permission="read",
        effect="allow",
    )
    timed_rule = ACLRule(
        role_id="r",
        category="entities",
        target_type="all",
        target_id=None,
        permission="control",
        effect="deny",
        conditions=_TIME_WINDOW,
    )

    # No time-window rule -> no timer scheduled.
    manager._store.async_get_rules.return_value = [plain_rule]
    with patch("homeassistant.auth.acl.async_track_time_interval") as track:
        manager._async_setup_time_tracking()
        track.assert_not_called()
    assert manager._unsub_time is None

    # A time-window rule -> timer scheduled.
    unsub = MagicMock()
    manager._store.async_get_rules.return_value = [timed_rule]
    with patch(
        "homeassistant.auth.acl.async_track_time_interval", return_value=unsub
    ) as track:
        manager._async_setup_time_tracking()
        track.assert_called_once()
    assert manager._unsub_time is unsub

    # Time-window rule removed -> existing timer cancelled.
    manager._store.async_get_rules.return_value = [plain_rule]
    with patch("homeassistant.auth.acl.async_track_time_interval") as track:
        manager._async_setup_time_tracking()
        track.assert_not_called()
    unsub.assert_called_once()
    assert manager._unsub_time is None


@pytest.mark.parametrize("priorities", [(0, 10), (10, 0)])
def test_compile_rules_deny_overrides_same_target(
    priorities: tuple[int, int],
) -> None:
    """A deny beats an allow on the same target+permission, regardless of order."""
    allow_pri, deny_pri = priorities
    manager = ACLManager.__new__(ACLManager)
    manager._store = MagicMock()
    manager._store.async_get_rules.return_value = [
        ACLRule(
            role_id="r",
            category="entities",
            target_type="all",
            target_id=None,
            permission="control",
            effect="allow",
            priority=allow_pri,
        ),
        ACLRule(
            role_id="r",
            category="entities",
            target_type="all",
            target_id=None,
            permission="control",
            effect="deny",
            priority=deny_pri,
        ),
    ]
    # Deny must win in both orderings — priority can't resurrect an allow.
    assert manager.compile_rules_to_policy("r") == {
        "entities": {"all": {"control": False}}
    }


def test_validate_rule_shape_rejects_mismatches() -> None:
    """Category must constrain target_type and permission."""
    validate_rule_shape("entities", "all", "control", "deny")  # valid
    validate_rule_shape("services", "service_ids", "control", "allow")  # valid
    with pytest.raises(ValueError, match="category"):
        validate_rule_shape("bogus", "all", "read", "deny")
    with pytest.raises(ValueError, match="effect"):
        validate_rule_shape("entities", "all", "read", "maybe")
    with pytest.raises(ValueError, match="target_type"):
        validate_rule_shape("services", "label_ids", "control", "deny")
    with pytest.raises(ValueError, match="permission"):
        validate_rule_shape("entities", "all", "manage", "deny")


def test_acl_rule_from_dict_rejects_invalid() -> None:
    """from_dict drops semantically invalid stored rules."""
    valid = {
        "id": "x",
        "role_id": "r",
        "category": "entities",
        "target_type": "all",
        "target_id": None,
        "permission": "control",
        "effect": "deny",
        "priority": 0,
        "created_at": "2026-06-01T00:00:00+00:00",
        "modified_at": "2026-06-01T00:00:00+00:00",
    }
    assert ACLRule.from_dict(valid).effect == "deny"
    with pytest.raises(ValueError, match="permission"):
        ACLRule.from_dict({**valid, "permission": "manage"})
    with pytest.raises(ValueError, match="conditions"):
        ACLRule.from_dict({**valid, "conditions": "not-a-dict"})
