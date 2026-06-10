"""Permissions for Home Assistant."""

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

import voluptuous as vol

from .admin import ADMIN_POLICY_SCHEMA, compile_groups
from .automations import AUTOMATION_POLICY_SCHEMA, compile_automations
from .const import (
    ADMIN_ESCALATE,
    ADMIN_GROUPS,
    ADMIN_MANAGE_GROUPS,
    CAT_ADMIN,
    CAT_AUTOMATIONS,
    CAT_ENTITIES,
    CAT_SERVICES,
    SCOPE_MANAGE,
    SCOPE_MANAGE_MEMBERS,
)
from .entities import ENTITY_POLICY_SCHEMA, compile_entities
from .merge import _contains_deny, merge_policies
from .models import PermissionLookup
from .services import SERVICE_POLICY_SCHEMA, compile_services
from .types import PolicyType
from .util import test_all

if TYPE_CHECKING:
    from ..models import User

POLICY_SCHEMA = vol.Schema(
    {
        vol.Optional(CAT_ENTITIES): ENTITY_POLICY_SCHEMA,
        vol.Optional(CAT_SERVICES): SERVICE_POLICY_SCHEMA,
        vol.Optional(CAT_AUTOMATIONS): AUTOMATION_POLICY_SCHEMA,
        vol.Optional(CAT_ADMIN): ADMIN_POLICY_SCHEMA,
    }
)

__all__ = [
    "POLICY_SCHEMA",
    "AbstractPermissions",
    "OwnerPermissions",
    "PermissionLookup",
    "PolicyPermissions",
    "PolicyType",
    "can_create_groups",
    "can_grant",
    "can_manage_group",
    "can_manage_members",
    "filter_entity_ids_by_permission",
    "merge_policies",
]


def filter_entity_ids_by_permission(
    user: User, entity_ids: Iterable[str], key: str
) -> list[str]:
    """Filter entity IDs to those the user can access for the given policy key."""
    if user.is_admin or user.permissions.access_all_entities(key):
        return list(entity_ids)
    check_entity = user.permissions.check_entity
    return [entity_id for entity_id in entity_ids if check_entity(entity_id, key)]


class AbstractPermissions:
    """Default permissions class."""

    _cached_entity_func: Callable[[str, str], bool] | None = None
    _cached_service_func: Callable[[str, str], bool] | None = None
    _cached_automation_func: Callable[[str, str], bool] | None = None
    _cached_group_admin_func: Callable[[str, str], bool] | None = None

    def _entity_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test entity access."""
        raise NotImplementedError

    def _service_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test service access."""
        raise NotImplementedError

    def _automation_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test automation access."""
        raise NotImplementedError

    def _group_admin_func(self) -> Callable[[str, str], bool]:
        """Return a function that tests per-group management scopes."""
        raise NotImplementedError

    @property
    def can_manage_groups(self) -> bool:
        """Global capability to create and delete custom groups."""
        return False

    @property
    def can_escalate(self) -> bool:
        """May grant permissions the user does not hold themselves."""
        return False

    def check_group_admin(self, group_id: str, scope: str) -> bool:
        """Check a per-group management scope (view/manage/manage_members)."""
        if (group_admin_func := self._cached_group_admin_func) is None:
            group_admin_func = self._cached_group_admin_func = self._group_admin_func()

        return group_admin_func(group_id, scope)

    def access_all_entities(self, key: str) -> bool:
        """Check if we have a certain access to all entities."""
        raise NotImplementedError

    def check_entity(self, entity_id: str, key: str) -> bool:
        """Check if we can access entity."""
        if (entity_func := self._cached_entity_func) is None:
            entity_func = self._cached_entity_func = self._entity_func()

        return entity_func(entity_id, key)

    def check_service(self, service_name: str, key: str) -> bool:
        """Check if we can access a service.

        Service name should be in format "domain.service".
        """
        if (service_func := self._cached_service_func) is None:
            service_func = self._cached_service_func = self._service_func()

        return service_func(service_name, key)

    def check_automation(self, entity_id: str, key: str) -> bool:
        """Check if we can access an automation/script/scene."""
        if (automation_func := self._cached_automation_func) is None:
            automation_func = self._cached_automation_func = self._automation_func()

        return automation_func(entity_id, key)


class PolicyPermissions(AbstractPermissions):
    """Handle permissions."""

    def __init__(self, policy: PolicyType, perm_lookup: PermissionLookup) -> None:
        """Initialize the permission class."""
        self._policy = policy
        self._perm_lookup = perm_lookup

    def access_all_entities(self, key: str) -> bool:
        """Check if we have a certain access to all entities."""
        return test_all(self._policy.get(CAT_ENTITIES), key)

    def _entity_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test entity access."""
        return compile_entities(self._policy.get(CAT_ENTITIES), self._perm_lookup)

    def _service_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test service access."""
        return compile_services(self._policy.get(CAT_SERVICES), self._perm_lookup)

    def _automation_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test automation access."""
        return compile_automations(
            self._policy.get(CAT_AUTOMATIONS), self._perm_lookup
        )

    def _group_admin_func(self) -> Callable[[str, str], bool]:
        """Return a function that tests per-group management scopes."""
        admin = self._policy.get(CAT_ADMIN)
        groups = admin.get(ADMIN_GROUPS) if isinstance(admin, dict) else admin
        return compile_groups(groups, self._perm_lookup)

    @property
    def can_manage_groups(self) -> bool:
        """Global capability to create and delete custom groups."""
        admin = self._policy.get(CAT_ADMIN)
        if admin is True:
            return True
        return isinstance(admin, dict) and admin.get(ADMIN_MANAGE_GROUPS) is True

    @property
    def can_escalate(self) -> bool:
        """May grant permissions the user does not hold themselves."""
        admin = self._policy.get(CAT_ADMIN)
        if admin is True:
            return True
        return isinstance(admin, dict) and admin.get(ADMIN_ESCALATE) is True

    def __eq__(self, other: object) -> bool:
        """Equals check."""
        return isinstance(other, PolicyPermissions) and other._policy == self._policy


class _OwnerPermissions(AbstractPermissions):
    """Owner permissions."""

    def access_all_entities(self, key: str) -> bool:
        """Check if we have a certain access to all entities."""
        return True

    def _entity_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test entity access."""
        return lambda entity_id, key: True

    def _service_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test service access."""
        return lambda service_name, key: True

    def _automation_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test automation access."""
        return lambda entity_id, key: True

    def _group_admin_func(self) -> Callable[[str, str], bool]:
        """Return a function that tests per-group management scopes."""
        return lambda group_id, scope: True

    @property
    def can_manage_groups(self) -> bool:
        """Global capability to create and delete custom groups."""
        return True

    @property
    def can_escalate(self) -> bool:
        """May grant permissions the user does not hold themselves."""
        return True


OwnerPermissions = _OwnerPermissions()


def can_create_groups(user: User) -> bool:
    """Whether a user may create/delete custom groups."""
    return user.is_admin or user.permissions.can_manage_groups


def can_manage_group(user: User, group_id: str) -> bool:
    """Whether a user may edit a group's policy / ACL rules."""
    return user.is_admin or user.permissions.check_group_admin(group_id, SCOPE_MANAGE)


def can_manage_members(user: User, group_id: str) -> bool:
    """Whether a user may add/remove members of a group."""
    return user.is_admin or user.permissions.check_group_admin(
        group_id, SCOPE_MANAGE_MEMBERS
    )


def _touches_permission(value: object) -> bool:
    """Whether a policy value sets any permission (an allow or a deny leaf)."""
    if value is True or value is False:
        return True
    if isinstance(value, dict):
        return any(_touches_permission(item) for item in value.values())
    return False


def _within_authority(granted: object, holder: object) -> bool:
    """Whether `holder` has authority over every permission `granted` sets.

    Setting a permission *either direction* requires the granter to hold it:
    you can't grant access you lack (escalation), and you can't impose a
    restriction on a scope you have no authority over (sabotage / lock-out).
    A subtree that sets nothing is always safe. Assumes `holder` has no deny
    carve-outs (callers enforce that), so a True leaf genuinely grants a node.
    """
    if not _touches_permission(granted):
        return True
    if granted is True or granted is False:
        return holder is True
    # granted is a dict that sets at least one permission
    if holder is True:
        return True
    if not isinstance(holder, dict):
        return False
    return all(
        _within_authority(value, holder.get(key)) for key, value in granted.items()
    )


def can_grant(user: User, policy: PolicyType) -> bool:
    """Escalation guard: may `user` grant everything `policy` allows?

    The owner and admins keep full management (they bypass). Anyone else may
    only set permissions — allow OR deny — over scopes they already hold, so
    they can neither escalate (grant access they lack) nor sabotage (restrict a
    scope they have no authority over), unless they carry `escalate`. This is
    the AWS/Azure stance that imposing a deny is a write that needs authority,
    not a free no-op.

    Sound but conservative: delegation is only exact from a holder whose own
    policy has no deny carve-outs. A holder whose policy contains denies must
    use `escalate` (or be admin/owner) — refining to a per-target check later.
    """
    if user.is_admin:
        return True
    perms = user.permissions
    if perms.can_escalate:
        return True
    holder = getattr(perms, "_policy", None)
    if not isinstance(holder, dict):
        return False
    # Delegating management authority itself (the 'admin' category) is a
    # meta-privilege: a plain manager may delegate access but never the power
    # to manage, so they can't mint a peer manager who could then lock them
    # out. Granting any admin scope requires escalate (handled above) or
    # admin/owner. Mirrors AWS gating iam: grants and k8s gating escalate/bind.
    if _touches_permission(policy.get(CAT_ADMIN)):
        return False
    if _contains_deny(list(holder.values())):
        return False
    return _within_authority(policy, holder)
