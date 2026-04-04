"""Tests for ACL manager."""

from homeassistant.auth.acl import ACLManager
from homeassistant.auth.acl.models import ACLRule


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
    from unittest.mock import MagicMock

    manager = ACLManager.__new__(ACLManager)
    manager._store = MagicMock()
    manager._store.async_get_rules.return_value = []

    policy = manager.compile_rules_to_policy("test-role")
    assert policy == {}


def test_compile_rules_single_allow() -> None:
    """Test compiling a single allow rule."""
    from unittest.mock import MagicMock

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
    from unittest.mock import MagicMock

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
    from unittest.mock import MagicMock

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
    from unittest.mock import MagicMock

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
