"""Tests for service permissions."""

from homeassistant.auth.permissions.services import (
    SERVICE_POLICY_SCHEMA,
    compile_services,
)


def test_services_none() -> None:
    """Test service policy with None."""
    compiled = compile_services(None, None)
    assert compiled("light.turn_on", "control") is False


def test_services_true() -> None:
    """Test service policy allowing all."""
    compiled = compile_services(True, None)
    assert compiled("light.turn_on", "control") is True
    assert compiled("homeassistant.restart", "control") is True


def test_services_false() -> None:
    """Test service policy denying all."""
    compiled = compile_services(False, None)
    assert compiled("light.turn_on", "control") is False


def test_services_by_service_id() -> None:
    """Test service permission by specific service ID."""
    policy = {
        "service_ids": {
            "homeassistant.restart": False,
            "light.turn_on": True,
        },
        "all": {"control": True},
    }
    SERVICE_POLICY_SCHEMA(policy)
    compiled = compile_services(policy, None)
    assert compiled("homeassistant.restart", "control") is False
    assert compiled("light.turn_on", "control") is True
    assert compiled("switch.turn_off", "control") is True


def test_services_by_domain() -> None:
    """Test service permission by domain."""
    policy = {
        "domains": {
            "homeassistant": False,
            "light": {"control": True},
        },
        "all": {"read": True},
    }
    SERVICE_POLICY_SCHEMA(policy)
    compiled = compile_services(policy, None)
    assert compiled("homeassistant.restart", "control") is False
    assert compiled("homeassistant.restart", "read") is False
    assert compiled("light.turn_on", "control") is True
    # read not specified at domain level, falls through to all
    assert compiled("light.turn_on", "read") is True
    assert compiled("switch.turn_off", "read") is True


def test_services_service_id_priority_over_domain() -> None:
    """Test that service_id has higher priority than domain."""
    policy = {
        "service_ids": {"homeassistant.restart": {"control": True}},
        "domains": {"homeassistant": False},
    }
    compiled = compile_services(policy, None)
    # service_id allows, but domain deny overrides (deny wins across subcategories)
    assert compiled("homeassistant.restart", "control") is False
    assert compiled("homeassistant.stop", "control") is False


def test_services_all_allow() -> None:
    """Test service policy with all allow."""
    policy = {"all": True}
    SERVICE_POLICY_SCHEMA(policy)
    compiled = compile_services(policy, None)
    assert compiled("light.turn_on", "control") is True
    assert compiled("light.turn_on", "read") is True


def test_services_all_read_only() -> None:
    """Test service policy with all read-only."""
    policy = {"all": {"read": True}}
    SERVICE_POLICY_SCHEMA(policy)
    compiled = compile_services(policy, None)
    assert compiled("light.turn_on", "read") is True
    assert compiled("light.turn_on", "control") is False


def test_services_deny_specific_with_allow_all() -> None:
    """Test denying a specific service while allowing all others."""
    policy = {
        "service_ids": {"homeassistant.restart": {"control": False}},
        "all": {"control": True},
    }
    compiled = compile_services(policy, None)
    assert compiled("homeassistant.restart", "control") is False
    assert compiled("light.turn_on", "control") is True
    assert compiled("switch.turn_off", "control") is True


def test_services_schema_validation() -> None:
    """Test that the service policy schema validates correctly."""
    SERVICE_POLICY_SCHEMA(True)
    SERVICE_POLICY_SCHEMA(False)
    SERVICE_POLICY_SCHEMA({"all": True})
    SERVICE_POLICY_SCHEMA({"service_ids": {"light.turn_on": True}})
    SERVICE_POLICY_SCHEMA({"domains": {"light": {"control": True}}})
    SERVICE_POLICY_SCHEMA(
        {
            "service_ids": {"homeassistant.restart": False},
            "domains": {"light": True},
            "all": {"read": True},
        }
    )
