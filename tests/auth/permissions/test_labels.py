"""Tests for label-based entity permissions."""

from homeassistant.auth.permissions.entities import (
    ENTITY_POLICY_SCHEMA,
    compile_entities,
)
from homeassistant.auth.permissions.models import PermissionLookup
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntry

from tests.common import RegistryEntryWithDefaults, mock_device_registry, mock_registry


def test_label_permission_allow(hass: HomeAssistant) -> None:
    """Test allowing entities by label."""
    entity_registry = mock_registry(
        hass,
        {
            "light.kitchen": RegistryEntryWithDefaults(
                entity_id="light.kitchen",
                unique_id="1234",
                platform="test_platform",
                labels={"room_lights"},
            ),
            "light.bedroom": RegistryEntryWithDefaults(
                entity_id="light.bedroom",
                unique_id="5678",
                platform="test_platform",
            ),
        },
    )
    device_registry = mock_device_registry(hass)

    policy = {"label_ids": {"room_lights": {"read": True, "control": True}}}
    ENTITY_POLICY_SCHEMA(policy)
    compiled = compile_entities(
        policy, PermissionLookup(entity_registry, device_registry)
    )
    assert compiled("light.kitchen", "read") is True
    assert compiled("light.kitchen", "control") is True
    assert compiled("light.kitchen", "edit") is False
    assert compiled("light.bedroom", "read") is False


def test_label_permission_deny(hass: HomeAssistant) -> None:
    """Test denying entities by label."""
    entity_registry = mock_registry(
        hass,
        {
            "light.kitchen": RegistryEntryWithDefaults(
                entity_id="light.kitchen",
                unique_id="1234",
                platform="test_platform",
                labels={"protected"},
            ),
            "light.bedroom": RegistryEntryWithDefaults(
                entity_id="light.bedroom",
                unique_id="5678",
                platform="test_platform",
            ),
        },
    )
    device_registry = mock_device_registry(hass)

    policy = {
        "label_ids": {"protected": False},
        "all": {"read": True, "control": True},
    }
    ENTITY_POLICY_SCHEMA(policy)
    compiled = compile_entities(
        policy, PermissionLookup(entity_registry, device_registry)
    )
    assert compiled("light.kitchen", "read") is False
    assert compiled("light.kitchen", "control") is False
    assert compiled("light.bedroom", "read") is True
    assert compiled("light.bedroom", "control") is True


def test_label_permission_partial_deny(hass: HomeAssistant) -> None:
    """Test denying specific permission by label."""
    entity_registry = mock_registry(
        hass,
        {
            "light.kitchen": RegistryEntryWithDefaults(
                entity_id="light.kitchen",
                unique_id="1234",
                platform="test_platform",
                labels={"protected"},
            ),
        },
    )
    device_registry = mock_device_registry(hass)

    policy = {
        "label_ids": {"protected": {"read": True, "control": False}},
        "all": {"read": True, "control": True},
    }
    compiled = compile_entities(
        policy, PermissionLookup(entity_registry, device_registry)
    )
    assert compiled("light.kitchen", "read") is True
    assert compiled("light.kitchen", "control") is False


def test_label_permission_true(hass: HomeAssistant) -> None:
    """Test allowing all permissions by label."""
    entity_registry = mock_registry(
        hass,
        {
            "light.kitchen": RegistryEntryWithDefaults(
                entity_id="light.kitchen",
                unique_id="1234",
                platform="test_platform",
                labels={"vip"},
            ),
        },
    )
    device_registry = mock_device_registry(hass)

    policy = {"label_ids": {"vip": True}}
    compiled = compile_entities(
        policy, PermissionLookup(entity_registry, device_registry)
    )
    assert compiled("light.kitchen", "read") is True
    assert compiled("light.kitchen", "control") is True
    assert compiled("light.kitchen", "edit") is True


def test_label_priority_vs_domain(hass: HomeAssistant) -> None:
    """Test that label has higher priority than domain."""
    entity_registry = mock_registry(
        hass,
        {
            "light.kitchen": RegistryEntryWithDefaults(
                entity_id="light.kitchen",
                unique_id="1234",
                platform="test_platform",
                labels={"protected"},
            ),
            "light.bedroom": RegistryEntryWithDefaults(
                entity_id="light.bedroom",
                unique_id="5678",
                platform="test_platform",
            ),
        },
    )
    device_registry = mock_device_registry(hass)

    policy = {
        "label_ids": {"protected": {"control": False}},
        "domains": {"light": {"read": True, "control": True}},
    }
    compiled = compile_entities(
        policy, PermissionLookup(entity_registry, device_registry)
    )
    # Label deny overrides domain allow
    assert compiled("light.kitchen", "control") is False
    # Read not specified at label level, falls through to domain
    assert compiled("light.kitchen", "read") is True
    # No label, domain allows
    assert compiled("light.bedroom", "control") is True


def test_label_priority_vs_entity_id(hass: HomeAssistant) -> None:
    """Test that entity_id has higher priority than label."""
    entity_registry = mock_registry(
        hass,
        {
            "light.kitchen": RegistryEntryWithDefaults(
                entity_id="light.kitchen",
                unique_id="1234",
                platform="test_platform",
                labels={"protected"},
            ),
        },
    )
    device_registry = mock_device_registry(hass)

    policy = {
        "entity_ids": {"light.kitchen": {"control": True}},
        "label_ids": {"protected": {"control": False}},
    }
    compiled = compile_entities(
        policy, PermissionLookup(entity_registry, device_registry)
    )
    # entity_id allows, but label deny overrides
    assert compiled("light.kitchen", "control") is False


def test_multiple_labels_deny_wins(hass: HomeAssistant) -> None:
    """Test that deny wins when entity has multiple matching labels."""
    entity_registry = mock_registry(
        hass,
        {
            "light.kitchen": RegistryEntryWithDefaults(
                entity_id="light.kitchen",
                unique_id="1234",
                platform="test_platform",
                labels={"room_lights", "protected"},
            ),
        },
    )
    device_registry = mock_device_registry(hass)

    policy = {
        "label_ids": {
            "room_lights": {"read": True, "control": True},
            "protected": {"control": False},
        },
    }
    compiled = compile_entities(
        policy, PermissionLookup(entity_registry, device_registry)
    )
    # "protected" deny wins over "room_lights" allow
    assert compiled("light.kitchen", "control") is False
    assert compiled("light.kitchen", "read") is True


def test_label_no_labels_entity(hass: HomeAssistant) -> None:
    """Test that entities without labels are unaffected by label permissions."""
    entity_registry = mock_registry(
        hass,
        {
            "light.kitchen": RegistryEntryWithDefaults(
                entity_id="light.kitchen",
                unique_id="1234",
                platform="test_platform",
            ),
        },
    )
    device_registry = mock_device_registry(hass)

    policy = {
        "label_ids": {"protected": False},
        "all": {"read": True},
    }
    compiled = compile_entities(
        policy, PermissionLookup(entity_registry, device_registry)
    )
    # No labels, falls through to "all"
    assert compiled("light.kitchen", "read") is True


def test_label_unknown_entity(hass: HomeAssistant) -> None:
    """Test label lookup for entity not in registry."""
    entity_registry = mock_registry(hass, {})
    device_registry = mock_device_registry(hass)

    policy = {
        "label_ids": {"protected": False},
        "all": {"read": True},
    }
    compiled = compile_entities(
        policy, PermissionLookup(entity_registry, device_registry)
    )
    # Entity not in registry, falls through to "all"
    assert compiled("light.unknown", "read") is True


def test_label_schema_validation() -> None:
    """Test that label_ids are accepted in the policy schema."""
    policy = {
        "label_ids": {
            "my_label": {"read": True, "control": False},
            "other_label": True,
        }
    }
    ENTITY_POLICY_SCHEMA(policy)

    policy_deny = {"label_ids": {"protected": False}}
    ENTITY_POLICY_SCHEMA(policy_deny)

    policy_all = {"label_ids": True}
    ENTITY_POLICY_SCHEMA(policy_all)
