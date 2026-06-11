"""Tests for delegated-management (admin) permissions."""

from types import SimpleNamespace

import pytest
import voluptuous as vol

from homeassistant.auth.permissions import (
    POLICY_SCHEMA,
    OwnerPermissions,
    PolicyPermissions,
    can_author_automations,
    can_create_groups,
    can_grant,
    can_manage_group,
    can_manage_members,
    can_modify_group,
    can_set_member,
)


def _user(
    policy: dict, *, is_admin: bool = False, is_owner: bool = False
) -> SimpleNamespace:
    """Minimal User stand-in with a PolicyPermissions object."""
    return SimpleNamespace(
        is_admin=is_admin or is_owner,
        is_owner=is_owner,
        permissions=PolicyPermissions(policy, None),
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


def _manager(*entities: str) -> SimpleNamespace:
    """A non-admin with manage/manage_members on 'team-a' plus entity control."""
    policy: dict = {
        "admin": {
            "groups": {
                "group_ids": {"team-a": {"manage": True, "manage_members": True}}
            }
        },
        "entities": {"entity_ids": {e: {"control": True} for e in entities}},
    }
    return _user(policy)


def test_can_modify_group_dominates_subordinate() -> None:
    """A manager may modify a group whose members it strictly dominates."""
    manager = _manager("light.a", "light.b")
    subordinate = _user({"entities": {"entity_ids": {"light.a": {"control": True}}}})
    assert can_modify_group(manager, "team-a", [manager, subordinate]) is True


def test_can_modify_group_blocks_peer_and_superior() -> None:
    """A manager may not modify a group containing a peer or a superior."""
    manager = _manager("light.a", "light.b")
    peer = _manager("light.a", "light.b")  # identical permissions
    superior = _manager("light.a", "light.b", "lock.door")
    assert can_modify_group(manager, "team-a", [manager, peer]) is False
    assert can_modify_group(manager, "team-a", [manager, superior]) is False


def test_can_modify_group_blocks_admin_and_owner_members() -> None:
    """A non-admin can't modify a group containing an admin or the owner."""
    manager = _manager("light.a")
    admin = _user({}, is_admin=True)
    owner = _user({}, is_owner=True)
    assert can_modify_group(manager, "team-a", [manager, admin]) is False
    assert can_modify_group(manager, "team-a", [manager, owner]) is False


def test_can_modify_group_blocks_real_peer_without_admin_scope() -> None:
    """A regular member with no admin key is still a protected peer.

    Regression for the admin-key asymmetry: a manager must not dominate a
    member whose *access* equals their own just because the manager carries an
    admin scope the member lacks.
    """
    manager = _manager("light.a")  # access: control light.a (+ admin scope)
    peer = _user({"entities": {"entity_ids": {"light.a": {"control": True}}}})  # no admin
    assert can_modify_group(manager, "team-a", [manager, peer]) is False


def test_can_set_member_requires_dominance() -> None:
    """Membership changes need manage_members AND strict dominance of the target."""
    manager = _manager("light.a", "light.b")
    subordinate = _user({"entities": {"entity_ids": {"light.a": {"control": True}}}})
    peer = _user(
        {"entities": {"entity_ids": {"light.a": {"control": True}, "light.b": {"control": True}}}}
    )
    admin = _user({}, is_admin=True)
    owner = _user({}, is_owner=True)
    # Can add/remove a strict subordinate...
    assert can_set_member(manager, "team-a", subordinate) is True
    # ...but not a peer, an admin, or the owner (no lock-out by removal).
    assert can_set_member(manager, "team-a", peer) is False
    assert can_set_member(manager, "team-a", admin) is False
    assert can_set_member(manager, "team-a", owner) is False
    # And not without the manage_members scope.
    no_scope = _user({"entities": {"entity_ids": {"light.a": {"control": True}}}})
    assert can_set_member(no_scope, "team-a", subordinate) is False


def test_can_modify_group_requires_manage_scope() -> None:
    """No manage scope -> can't modify regardless of dominance."""
    no_scope = _user({"entities": {"entity_ids": {"light.a": {"control": True}}}})
    sub = _user({})
    assert can_modify_group(no_scope, "team-a", [no_scope, sub]) is False


def test_can_modify_group_owner_and_admin() -> None:
    """The owner dominates everyone; an admin dominates non-admins but not peers."""
    owner = _user({}, is_owner=True)
    admin = _user({}, is_admin=True)
    other_admin = _user({}, is_admin=True)
    regular = _user({"entities": {"entity_ids": {"light.a": {"control": True}}}})
    assert can_modify_group(owner, "any", [owner, admin, regular]) is True
    assert can_modify_group(admin, "any", [admin, regular]) is True
    # An admin cannot modify a group containing a peer admin (or the owner).
    assert can_modify_group(admin, "any", [admin, other_admin]) is False
    assert can_modify_group(admin, "any", [admin, owner]) is False


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


def test_can_author_automations() -> None:
    """Admins and users with manage_automations may author automations."""
    assert can_author_automations(_user({}, is_admin=True)) is True
    assert can_author_automations(_user({"admin": {"manage_automations": True}})) is True
    assert can_author_automations(_user({})) is False
