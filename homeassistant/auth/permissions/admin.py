"""Management (delegated-administration) permissions.

A user's ``admin`` policy describes what they may *manage*, separate from what
they may access. It carries two global flags plus per-group scopes:

- ``manage_groups``: create and delete custom groups.
- ``escalate``: grant permissions the user does not hold themselves (the
  Kubernetes RBAC "escalate" rule). Without it, a delegated manager can only
  grant a subset of their own permissions.
- ``groups``: per-group ``view`` / ``manage`` / ``manage_members`` scopes,
  keyed by group id (or ``all``), modelled on Keycloak's group permissions.

These are enforced at the management API boundary, not in the runtime
entity/service access path.
"""

from collections import OrderedDict
from collections.abc import Callable

import voluptuous as vol

from .const import GROUP_IDS, SCOPE_MANAGE, SCOPE_MANAGE_MEMBERS, SCOPE_VIEW, SUBCAT_ALL
from .models import PermissionLookup
from .types import CategoryType, SubCategoryDict, ValueType
from .util import SubCatLookupType, compile_policy, lookup_all

SINGLE_GROUP_SCHEMA = vol.Any(
    True,
    False,
    vol.Schema(
        {
            vol.Optional(SCOPE_VIEW): vol.Any(True, False),
            vol.Optional(SCOPE_MANAGE): vol.Any(True, False),
            vol.Optional(SCOPE_MANAGE_MEMBERS): vol.Any(True, False),
            vol.Optional(SUBCAT_ALL): vol.Any(True, False),
        }
    ),
)

GROUPS_SCHEMA = vol.Any(
    True,
    False,
    vol.Schema(
        {
            vol.Optional(SUBCAT_ALL): SINGLE_GROUP_SCHEMA,
            vol.Optional(GROUP_IDS): vol.Schema({str: SINGLE_GROUP_SCHEMA}),
        }
    ),
)

ADMIN_POLICY_SCHEMA = vol.Any(
    True,
    False,
    vol.Schema(
        {
            vol.Optional("manage_groups"): vol.Any(True, False),
            vol.Optional("manage_automations"): vol.Any(True, False),
            vol.Optional("escalate"): vol.Any(True, False),
            vol.Optional("groups"): GROUPS_SCHEMA,
        }
    ),
)


def _lookup_group_id(
    perm_lookup: PermissionLookup, groups_dict: SubCategoryDict, group_id: str
) -> ValueType | None:
    """Look up a group-management scope by group id."""
    return groups_dict.get(group_id)


def compile_groups(
    policy: CategoryType, perm_lookup: PermissionLookup
) -> Callable[[str, str], bool]:
    """Compile the per-group ``groups`` policy into a (group_id, scope) test."""
    subcategories: SubCatLookupType = OrderedDict()
    subcategories[GROUP_IDS] = _lookup_group_id
    subcategories[SUBCAT_ALL] = lookup_all

    return compile_policy(policy, subcategories, perm_lookup)
