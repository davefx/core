"""Automation, script, and scene permissions."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable

import voluptuous as vol

from .const import (
    ENTITY_LABEL_IDS,
    POLICY_EDIT,
    POLICY_READ,
    POLICY_TRIGGER,
    SUBCAT_ALL,
)
from .models import PermissionLookup
from .types import CategoryType, SubCategoryDict, ValueType
from .util import SubCatLookupType, compile_policy, lookup_all

SINGLE_AUTOMATION_SCHEMA = vol.Any(
    True,
    False,
    vol.Schema(
        {
            vol.Optional(POLICY_READ): vol.Any(True, False),
            vol.Optional(POLICY_EDIT): vol.Any(True, False),
            vol.Optional(POLICY_TRIGGER): vol.Any(True, False),
            vol.Optional(SUBCAT_ALL): vol.Any(True, False),
        }
    ),
)

AUTOMATION_ENTITY_IDS = "entity_ids"

AUTOMATION_VALUES_SCHEMA = vol.Any(
    True, False, vol.Schema({str: SINGLE_AUTOMATION_SCHEMA})
)

AUTOMATION_POLICY_SCHEMA = vol.Any(
    True,
    False,
    vol.Schema(
        {
            vol.Optional(SUBCAT_ALL): SINGLE_AUTOMATION_SCHEMA,
            vol.Optional(AUTOMATION_ENTITY_IDS): AUTOMATION_VALUES_SCHEMA,
            vol.Optional(ENTITY_LABEL_IDS): AUTOMATION_VALUES_SCHEMA,
        }
    ),
)


def _lookup_automation_id(
    perm_lookup: PermissionLookup,
    automations_dict: SubCategoryDict,
    entity_id: str,
) -> ValueType | None:
    """Look up automation permission by entity id."""
    return automations_dict.get(entity_id)


def _lookup_automation_label(
    perm_lookup: PermissionLookup,
    labels_dict: SubCategoryDict,
    entity_id: str,
) -> ValueType | None:
    """Look up automation permission by label."""
    entity_entry = perm_lookup.entity_registry.async_get(entity_id)

    if entity_entry is None or not entity_entry.labels:
        return None

    for label in entity_entry.labels:
        label_perm = labels_dict.get(label)
        if label_perm is not None:
            if label_perm is False:
                return False
            return label_perm

    return None


def compile_automations(
    policy: CategoryType, perm_lookup: PermissionLookup
) -> Callable[[str, str], bool]:
    """Compile automation policy into a function that tests permission."""
    subcategories: SubCatLookupType = OrderedDict()
    subcategories[AUTOMATION_ENTITY_IDS] = _lookup_automation_id
    subcategories[ENTITY_LABEL_IDS] = _lookup_automation_label
    subcategories[SUBCAT_ALL] = lookup_all

    return compile_policy(policy, subcategories, perm_lookup)
