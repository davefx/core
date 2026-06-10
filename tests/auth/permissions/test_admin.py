"""Tests for delegated-management (admin) permissions."""

from types import SimpleNamespace

import pytest
import voluptuous as vol

from homeassistant.auth.permissions import (
    POLICY_SCHEMA,
    OwnerPermissions,
    PolicyPermissions,
    can_create_groups,
    can_grant,
    can_manage_group,
    can_manage_members,
)


def _user(policy: dict, *, is_admin: bool = False) -> SimpleNamespace:
    """Minimal User stand-in with a PolicyPermissions object."""
    return SimpleNamespace(
        is_admin=is_admin, permissions=PolicyPermissions(policy, None)
    )


def test_policy_schema_accepts_admin_category() -> None:
    """The admin category and its scopes validate."""
    policy = POLICY_SCHEMA(
        {
            "admin": {
                "manage_groups": True,
                "escalate": False,
                "groups": {
                    "all": {"view": True},
                    "group_ids": {"team-a": {"manage": True, "manage_members": True}},
                },
            }
        }
    )
    assert set(policy["admin"]) == {"manage_groups", "escalate", "groups"}


def test_policy_schema_rejects_unknown_scope() -> None:
    """Unknown management scopes are rejected."""
    with pytest.raises(vol.Invalid):
        POLICY_SCHEMA({"admin": {"groups": {"group_ids": {"t": {"bogus": True}}}}})


def test_per_group_scopes() -> None:
    """check_group_admin resolves the right scope per group."""
    perms = PolicyPermissions(
        {
            "admin": {
                "groups": {"group_ids": {"team-a": {"manage": True, "manage_members": True}}}
            }
        },
        None,
    )
    assert perms.check_group_admin("team-a", "manage") is True
    assert perms.check_group_admin("team-a", "manage_members") is True
    assert perms.check_group_admin("team-a", "view") is False
    assert perms.check_group_admin("team-b", "manage") is False


def test_global_flags() -> None:
    """manage_groups and escalate flags read from the admin policy."""
    perms = PolicyPermissions({"admin": {"manage_groups": True}}, None)
    assert perms.can_manage_groups is True
    assert perms.can_escalate is False
    none = PolicyPermissions({}, None)
    assert none.can_manage_groups is False
    assert none.can_escalate is False


def test_owner_manages_everything() -> None:
    """The owner holds all management capabilities."""
    assert OwnerPermissions.check_group_admin("anything", "manage") is True
    assert OwnerPermissions.can_manage_groups is True
    assert OwnerPermissions.can_escalate is True


def test_management_helpers_admin_bypass() -> None:
    """Admins keep full management regardless of policy."""
    admin = _user({}, is_admin=True)
    assert can_create_groups(admin) is True
    assert can_manage_group(admin, "team-a") is True
    assert can_manage_members(admin, "team-a") is True


def test_management_helpers_delegated() -> None:
    """A non-admin only manages what their scopes grant."""
    user = _user(
        {"admin": {"groups": {"group_ids": {"team-a": {"manage_members": True}}}}}
    )
    assert can_manage_members(user, "team-a") is True
    assert can_manage_members(user, "team-b") is False
    assert can_manage_group(user, "team-a") is False  # only manage_members granted
    assert can_create_groups(user) is False


def test_can_grant_escalation_guard() -> None:
    """A non-admin may grant only a subset of what they already hold."""
    holder = _user({"entities": {"entity_ids": {"light.kitchen": {"control": True}}}})
    within = {"entities": {"entity_ids": {"light.kitchen": {"control": True}}}}
    beyond = {"entities": {"entity_ids": {"lock.door": {"control": True}}}}
    assert can_grant(holder, within) is True
    assert can_grant(holder, beyond) is False


def test_can_grant_deny_requires_authority() -> None:
    """Imposing a deny needs authority over the scope (no free sabotage)."""
    holder = _user({"entities": {"entity_ids": {"light.kitchen": {"control": True}}}})
    # Can deny a scope you hold...
    assert (
        can_grant(holder, {"entities": {"entity_ids": {"light.kitchen": {"control": False}}}})
        is True
    )
    # ...but not a scope you don't hold, and not a blanket deny.
    assert (
        can_grant(holder, {"entities": {"entity_ids": {"lock.door": {"control": False}}}})
        is False
    )
    assert can_grant(holder, {"entities": {"all": {"control": False}}}) is False


def test_can_grant_management_authority_needs_escalate() -> None:
    """Delegating the 'admin' category itself requires escalate.

    Stops a plain manager from minting a peer manager who could lock them out.
    """
    grant_mgmt = {"admin": {"groups": {"group_ids": {"team-a": {"manage": True}}}}}
    manager = _user(
        {"admin": {"groups": {"group_ids": {"team-a": {"manage": True}}}}}
    )
    assert can_grant(manager, grant_mgmt) is False
    escalator = _user(
        {"admin": {"escalate": True, "groups": {"group_ids": {"team-a": {"manage": True}}}}}
    )
    assert can_grant(escalator, grant_mgmt) is True


def test_can_grant_escalate_capability() -> None:
    """The escalate flag lets a non-admin grant beyond their own permissions."""
    holder = _user(
        {
            "entities": {"entity_ids": {"light.kitchen": {"control": True}}},
            "admin": {"escalate": True},
        }
    )
    assert can_grant(holder, {"entities": {"entity_ids": {"lock.door": {"control": True}}}}) is True


def test_can_grant_admin_and_owner_bypass() -> None:
    """Admins and the owner are not constrained by the escalation guard."""
    admin = _user({}, is_admin=True)
    assert can_grant(admin, {"entities": True}) is True


def test_can_grant_deny_holder_is_conservative() -> None:
    """A holder with deny carve-outs can't delegate without escalate."""
    holder = _user(
        {
            "entities": {
                "all": {"control": True},
                "entity_ids": {"lock.door": {"control": False}},
            }
        }
    )
    # Conservatively refused (would otherwise risk granting the carved-out lock).
    assert can_grant(holder, {"entities": {"all": {"control": True}}}) is False
