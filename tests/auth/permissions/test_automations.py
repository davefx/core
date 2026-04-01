"""Tests for automation permissions."""

from homeassistant.auth.permissions.automations import (
    AUTOMATION_POLICY_SCHEMA,
    compile_automations,
)
from homeassistant.auth.permissions.models import PermissionLookup
from homeassistant.core import HomeAssistant

from tests.common import RegistryEntryWithDefaults, mock_device_registry, mock_registry


def test_automations_none() -> None:
    """Test automation policy with None."""
    compiled = compile_automations(None, None)
    assert compiled("automation.morning_lights", "read") is False


def test_automations_true() -> None:
    """Test automation policy allowing all."""
    compiled = compile_automations(True, None)
    assert compiled("automation.morning_lights", "read") is True
    assert compiled("automation.morning_lights", "edit") is True
    assert compiled("automation.morning_lights", "trigger") is True


def test_automations_false() -> None:
    """Test automation policy denying all."""
    compiled = compile_automations(False, None)
    assert compiled("automation.morning_lights", "read") is False


def test_automations_by_entity_id() -> None:
    """Test automation permission by entity ID."""
    policy = {
        "entity_ids": {
            "automation.morning_lights": {"read": True, "trigger": True},
            "automation.security_alarm": {"read": True, "edit": False},
        },
    }
    AUTOMATION_POLICY_SCHEMA(policy)
    compiled = compile_automations(policy, None)
    assert compiled("automation.morning_lights", "read") is True
    assert compiled("automation.morning_lights", "trigger") is True
    assert compiled("automation.morning_lights", "edit") is False
    assert compiled("automation.security_alarm", "read") is True
    assert compiled("automation.security_alarm", "edit") is False
    assert compiled("automation.unknown", "read") is False


def test_automations_by_label(hass: HomeAssistant) -> None:
    """Test automation permission by label."""
    entity_registry = mock_registry(
        hass,
        {
            "automation.morning_lights": RegistryEntryWithDefaults(
                entity_id="automation.morning_lights",
                unique_id="1234",
                platform="automation",
                labels={"daily_routines"},
            ),
            "automation.security_alarm": RegistryEntryWithDefaults(
                entity_id="automation.security_alarm",
                unique_id="5678",
                platform="automation",
                labels={"protected"},
            ),
        },
    )
    device_registry = mock_device_registry(hass)

    policy = {
        "label_ids": {
            "daily_routines": {"read": True, "trigger": True, "edit": True},
            "protected": {"read": True, "edit": False, "trigger": False},
        },
    }
    compiled = compile_automations(
        policy, PermissionLookup(entity_registry, device_registry)
    )
    assert compiled("automation.morning_lights", "read") is True
    assert compiled("automation.morning_lights", "edit") is True
    assert compiled("automation.morning_lights", "trigger") is True
    assert compiled("automation.security_alarm", "read") is True
    assert compiled("automation.security_alarm", "edit") is False
    assert compiled("automation.security_alarm", "trigger") is False


def test_automations_all_read_trigger() -> None:
    """Test automation policy with all read and trigger."""
    policy = {"all": {"read": True, "trigger": True}}
    AUTOMATION_POLICY_SCHEMA(policy)
    compiled = compile_automations(policy, None)
    assert compiled("automation.test", "read") is True
    assert compiled("automation.test", "trigger") is True
    assert compiled("automation.test", "edit") is False


def test_automations_deny_specific_with_allow_all() -> None:
    """Test denying edit on specific automation while allowing all."""
    policy = {
        "entity_ids": {"automation.critical": {"edit": False, "trigger": False}},
        "all": {"read": True, "edit": True, "trigger": True},
    }
    compiled = compile_automations(policy, None)
    # read is not denied at entity_ids level, falls through to all
    assert compiled("automation.critical", "read") is True
    assert compiled("automation.critical", "edit") is False
    assert compiled("automation.critical", "trigger") is False
    assert compiled("automation.other", "edit") is True
    assert compiled("automation.other", "trigger") is True


def test_automations_schema_validation() -> None:
    """Test that the automation policy schema validates correctly."""
    AUTOMATION_POLICY_SCHEMA(True)
    AUTOMATION_POLICY_SCHEMA(False)
    AUTOMATION_POLICY_SCHEMA({"all": {"read": True, "trigger": True}})
    AUTOMATION_POLICY_SCHEMA(
        {"entity_ids": {"automation.test": {"read": True, "edit": False}}}
    )
    AUTOMATION_POLICY_SCHEMA({"label_ids": {"protected": False}})
