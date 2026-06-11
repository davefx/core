"""Permissions for Home Assistant."""

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

import voluptuous as vol

from .admin import ADMIN_POLICY_SCHEMA, compile_groups
from .automations import AUTOMATION_POLICY_SCHEMA, compile_automations
from .const import (
    ADMIN_ESCALATE,
    ADMIN_GROUPS,
    ADMIN_MANAGE_AUTOMATIONS,
    ADMIN_MANAGE_GROUPS,
    ADMIN_MANAGE_SCENES,
    ADMIN_MANAGE_SCRIPTS,
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
    "can_author_automations",
    "can_create_groups",
    "can_grant",
    "can_manage_group",
    "can_manage_members",
    "can_modify_group",
    "can_set_automation_owner",
    "can_set_member",
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
    def can_manage_automations(self) -> bool:
        """Global capability to author automations."""
        return False

    @property
    def can_manage_scripts(self) -> bool:
        """Global capability to author scripts."""
        return False

    @property
    def can_manage_scenes(self) -> bool:
        """Global capability to author scenes."""
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
    def can_manage_automations(self) -> bool:
        """Global capability to author automations."""
        admin = self._policy.get(CAT_ADMIN)
        if admin is True:
            return True
        return isinstance(admin, dict) and admin.get(ADMIN_MANAGE_AUTOMATIONS) is True

    @property
    def can_manage_scripts(self) -> bool:
        """Global capability to author scripts."""
        admin = self._policy.get(CAT_ADMIN)
        if admin is True:
            return True
        return isinstance(admin, dict) and admin.get(ADMIN_MANAGE_SCRIPTS) is True

    @property
    def can_manage_scenes(self) -> bool:
        """Global capability to author scenes."""
        admin = self._policy.get(CAT_ADMIN)
        if admin is True:
            return True
        return isinstance(admin, dict) and admin.get(ADMIN_MANAGE_SCENES) is True

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
    def can_manage_automations(self) -> bool:
        """Global capability to author automations."""
        return True

    @property
    def can_manage_scripts(self) -> bool:
        """Global capability to author scripts."""
        return True

    @property
    def can_manage_scenes(self) -> bool:
        """Global capability to author scenes."""
        return True

    @property
    def can_escalate(self) -> bool:
        """May grant permissions the user does not hold themselves."""
        return True


OwnerPermissions = _OwnerPermissions()


def can_create_groups(user: User) -> bool:
    """Whether a user may create/delete custom groups."""
    return user.is_admin or user.permissions.can_manage_groups


def can_author_automations(user: User) -> bool:
    """Whether a user may create/edit/delete automations."""
    return user.is_admin or user.permissions.can_manage_automations


def can_author_scripts(user: User) -> bool:
    """Whether a user may create/edit/delete scripts."""
    return user.is_admin or user.permissions.can_manage_scripts


def can_author_scenes(user: User) -> bool:
    """Whether a user may create/edit/delete scenes."""
    return user.is_admin or user.permissions.can_manage_scenes


def can_set_automation_owner(
    actor: User, current_owner: User | None, new_owner: User
) -> bool:
    """Whether `actor` may set an automation's run-as owner to `new_owner`.

    Ownership transfer / adoption. The actor must be allowed to author
    automations (or already be the owner handing off their own), and must
    strictly dominate or equal *both* the current owner (no stealing a
    peer/superior's automation) and the new owner (no making a superior run an
    automation you control — confused-deputy escalation).
    """
    is_current = current_owner is not None and current_owner.id == actor.id
    if not (can_author_automations(actor) or is_current):
        return False
    if current_owner is not None and not _user_dominates(actor, current_owner):
        return False
    return _user_dominates(actor, new_owner)


def can_manage_group(user: User, group_id: str) -> bool:
    """Whether a user may edit a group's policy / ACL rules."""
    return user.is_admin or user.permissions.check_group_admin(group_id, SCOPE_MANAGE)


def can_manage_members(user: User, group_id: str) -> bool:
    """Whether a user may add/remove members of a group."""
    return user.is_admin or user.permissions.check_group_admin(
        group_id, SCOPE_MANAGE_MEMBERS
    )


def can_set_member(user: User, group_id: str, target: User) -> bool:
    """Whether `user` may add or remove `target` as a member of a group.

    Needs the manage_members scope AND strict dominance of the target: you
    can't remove (lock out) a peer/superior, nor pull one out of a shared group
    to then edit it freely. For an *add*, the caller must also check
    can_grant(user, group_policy) so a manager can't drop a user into a group
    that grants or denies beyond the manager's own authority.
    """
    return can_manage_members(user, group_id) and _user_dominates(user, target)


def can_modify_group(user: User, group_id: str, members: Iterable[User]) -> bool:
    """Whether `user` may modify a group, given its current member users.

    Beyond holding the `manage` scope, the user must *strictly dominate* every
    other member, so a manager can't restrict a peer or a more-privileged
    member of a shared group (the privilege-ordering rule). The owner dominates
    everyone and can never be dominated.
    """
    if not can_manage_group(user, group_id):
        return False
    return all(
        _user_dominates(user, member) for member in members if member is not user
    )


def _has_allow(value: object) -> bool:
    """Whether a policy value grants anything (a True leaf somewhere)."""
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_has_allow(item) for item in value.values())
    return False


def _allow_subset(sub: object, sup: object) -> bool:
    """Whether every allow in `sub` is also allowed by `sup`."""
    if not _has_allow(sub):
        return True
    if sub is True:
        return sup is True
    if sup is True:
        return True
    if not isinstance(sub, dict) or not isinstance(sup, dict):
        return False
    return all(_allow_subset(value, sup.get(key)) for key, value in sub.items())


def _user_dominates(superior: User, member: User) -> bool:
    """Whether `superior` is strictly more privileged than `member`.

    Owner > admin > regular users; among regular users, by proper superset of
    granted permissions. Conservative: a would-be superior whose own policy has
    deny carve-outs cannot be shown to dominate (so modification is refused).
    """
    if superior is member or superior.is_owner:
        return True
    if member.is_owner or member.is_admin:
        # Nobody but the owner dominates the owner; a non-owner doesn't
        # dominate an admin (and peer admins don't dominate each other).
        return False
    if superior.is_admin:
        return True
    sup_policy = getattr(superior.permissions, "_policy", None)
    mem_policy = getattr(member.permissions, "_policy", None)
    if not isinstance(sup_policy, dict) or _contains_deny(list(sup_policy.values())):
        return False
    if not isinstance(mem_policy, dict):
        mem_policy = {}
    # Dominance is about access, not management scopes: exclude the admin
    # category, otherwise a manager (who always carries an admin scope a plain
    # member lacks) would "strictly dominate" even an access-equal peer.
    sup_access = {key: val for key, val in sup_policy.items() if key != CAT_ADMIN}
    mem_access = {key: val for key, val in mem_policy.items() if key != CAT_ADMIN}
    # superior covers everything member is allowed, and holds something more
    return _allow_subset(mem_access, sup_access) and not _allow_subset(
        sup_access, mem_access
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
