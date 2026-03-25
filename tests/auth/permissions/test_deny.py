"""Tests for deny-overrides-allow permission semantics."""

from homeassistant.auth.permissions.entities import compile_entities
from homeassistant.auth.permissions.merge import merge_policies
from homeassistant.auth.permissions.models import PermissionLookup
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntry

from tests.common import RegistryEntryWithDefaults, mock_device_registry, mock_registry


def test_deny_entity_id() -> None:
    """Test denying a specific entity by entity ID."""
    policy = {
        "entity_ids": {"light.kitchen": False},
        "all": {"read": True, "control": True},
    }
    compiled = compile_entities(policy, None)
    assert compiled("light.kitchen", "read") is False
    assert compiled("light.kitchen", "control") is False
    assert compiled("light.bedroom", "read") is True
    assert compiled("light.bedroom", "control") is True


def test_deny_entity_id_partial() -> None:
    """Test denying only specific permission on an entity."""
    policy = {
        "entity_ids": {"light.kitchen": {"read": True, "control": False}},
        "all": {"read": True, "control": True},
    }
    compiled = compile_entities(policy, None)
    assert compiled("light.kitchen", "read") is True
    assert compiled("light.kitchen", "control") is False
    assert compiled("light.bedroom", "control") is True


def test_deny_domain() -> None:
    """Test denying an entire domain."""
    policy = {
        "domains": {"light": False},
        "all": {"read": True, "control": True},
    }
    compiled = compile_entities(policy, None)
    assert compiled("light.kitchen", "read") is False
    assert compiled("light.kitchen", "control") is False
    assert compiled("switch.kitchen", "read") is True
    assert compiled("switch.kitchen", "control") is True


def test_deny_domain_partial() -> None:
    """Test denying specific permission on a domain."""
    policy = {
        "domains": {"light": {"read": True, "control": False}},
        "all": {"read": True, "control": True},
    }
    compiled = compile_entities(policy, None)
    assert compiled("light.kitchen", "read") is True
    assert compiled("light.kitchen", "control") is False
    assert compiled("switch.kitchen", "control") is True


def test_deny_overrides_allow_across_subcategories() -> None:
    """Test that deny in any subcategory overrides allow in another."""
    policy = {
        "entity_ids": {"light.kitchen": True},
        "domains": {"light": {"control": False}},
        "all": {"read": True, "control": True},
    }
    compiled = compile_entities(policy, None)
    # entity_ids allows light.kitchen, but domain-level deny overrides
    assert compiled("light.kitchen", "read") is True
    assert compiled("light.kitchen", "control") is False


def test_deny_device(hass: HomeAssistant) -> None:
    """Test denying by device ID."""
    entity_registry = mock_registry(
        hass,
        {
            "light.kitchen": RegistryEntryWithDefaults(
                entity_id="light.kitchen",
                unique_id="1234",
                platform="test_platform",
                device_id="mock-dev-id",
            ),
            "light.bedroom": RegistryEntryWithDefaults(
                entity_id="light.bedroom",
                unique_id="5678",
                platform="test_platform",
                device_id="mock-dev-id-2",
            ),
        },
    )
    device_registry = mock_device_registry(hass)

    policy = {
        "device_ids": {"mock-dev-id": False},
        "all": {"read": True, "control": True},
    }
    compiled = compile_entities(
        policy, PermissionLookup(entity_registry, device_registry)
    )
    assert compiled("light.kitchen", "read") is False
    assert compiled("light.kitchen", "control") is False
    assert compiled("light.bedroom", "read") is True


def test_deny_all_category() -> None:
    """Test deny at the all subcategory level."""
    policy = {"all": False}
    compiled = compile_entities(policy, None)
    assert compiled("light.kitchen", "read") is False
    assert compiled("switch.kitchen", "control") is False


def test_deny_all_partial() -> None:
    """Test deny specific permission at the all level."""
    policy = {"all": {"read": True, "control": False}}
    compiled = compile_entities(policy, None)
    assert compiled("light.kitchen", "read") is True
    assert compiled("light.kitchen", "control") is False


def test_deny_category_level() -> None:
    """Test False at the entire category level."""
    compiled = compile_entities(False, None)
    assert compiled("light.kitchen", "read") is False
    assert compiled("light.kitchen", "control") is False


def test_merge_deny_at_leaf() -> None:
    """Test that deny wins over allow when merging at leaf level."""
    policy1 = {"entities": {"entity_ids": {"light.kitchen": {"control": True}}}}
    policy2 = {"entities": {"entity_ids": {"light.kitchen": {"control": False}}}}
    merged = merge_policies([policy1, policy2])
    assert merged == {
        "entities": {"entity_ids": {"light.kitchen": {"control": False}}}
    }


def test_merge_deny_category_level() -> None:
    """Test that False at category level wins."""
    policy1 = {"entities": True}
    policy2 = {"entities": False}
    merged = merge_policies([policy1, policy2])
    assert merged == {"entities": False}


def test_merge_deny_subcategory_with_allow_all() -> None:
    """Test deny in dict source when another source is True."""
    policy1 = {"entities": True}
    policy2 = {"entities": {"entity_ids": {"alarm.main": {"control": False}}}}
    merged = merge_policies([policy1, policy2])
    # True is expanded to {all: True} and deny is preserved
    compiled = compile_entities(merged["entities"], None)
    assert compiled("alarm.main", "control") is False
    assert compiled("alarm.main", "read") is True
    assert compiled("light.kitchen", "read") is True
    assert compiled("light.kitchen", "control") is True


def test_merge_no_deny_true_wins() -> None:
    """Test backward compatibility: True wins when no deny values exist."""
    policy1 = {"entities": True}
    policy2 = {"entities": {"entity_ids": {"light.kitchen": True}}}
    merged = merge_policies([policy1, policy2])
    # No denies, True wins outright (backward compatible)
    assert merged == {"entities": True}


def test_merge_three_sources_with_deny() -> None:
    """Test merging three policies where one has deny."""
    policy1 = {"entities": {"all": {"read": True, "control": True}}}
    policy2 = {"entities": {"entity_ids": {"alarm.main": True}}}
    policy3 = {"entities": {"entity_ids": {"alarm.main": {"control": False}}}}
    merged = merge_policies([policy1, policy2, policy3])
    compiled = compile_entities(merged["entities"], None)
    assert compiled("alarm.main", "read") is True
    assert compiled("alarm.main", "control") is False
    assert compiled("light.kitchen", "read") is True
    assert compiled("light.kitchen", "control") is True


def test_merge_backward_compat_no_deny() -> None:
    """Test that policies without deny values merge as before."""
    policy1 = {"entities": {"entity_ids": {"light.kitchen": True}}}
    policy2 = {"entities": {"domains": {"switch": {"read": True}}}}
    merged = merge_policies([policy1, policy2])
    assert merged == {
        "entities": {
            "entity_ids": {"light.kitchen": True},
            "domains": {"switch": {"read": True}},
        }
    }


def test_deny_none_interaction() -> None:
    """Test that None (no opinion) does not trigger deny."""
    policy1 = {"entities": {"entity_ids": {"light.kitchen": None}}}
    policy2 = {"entities": {"entity_ids": {"light.kitchen": True}}}
    merged = merge_policies([policy1, policy2])
    assert merged == {"entities": {"entity_ids": {"light.kitchen": True}}}
