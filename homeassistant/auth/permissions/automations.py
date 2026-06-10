"""Automation, script, and scene permissions."""

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
    """Look up automation permission by label.

    An automation/script/scene can have multiple labels. Permissions from all
    matching labels are merged with deny-overrides-allow semantics, mirroring
    the entity label lookup: a deny on any label wins regardless of label set
    iteration order (labels are an unordered set).
    """
    entity_entry = perm_lookup.entity_registry.async_get(entity_id)

    if entity_entry is None or not entity_entry.labels:
        return None

    matching: list[ValueType] = []
    for label in entity_entry.labels:
        label_perm = labels_dict.get(label)
        if label_perm is not None:
            matching.append(label_perm)

    if not matching:
        return None

    # Deny (False) on any label wins.
    if any(perm is False for perm in matching):
        return False

    # Allow-all (True) with no deny wins.
    if any(perm is True for perm in matching):
        return True

    # All matches are dicts — merge per key, deny wins.
    merged: dict[str, bool] = {}
    for perm in matching:
        assert isinstance(perm, dict)
        for key, value in perm.items():
            if key not in merged:
                merged[key] = value
            elif value is False:
                merged[key] = False

    return merged or None


def compile_automations(
    policy: CategoryType, perm_lookup: PermissionLookup
) -> Callable[[str, str], bool]:
    """Compile automation policy into a function that tests permission."""
    subcategories: SubCatLookupType = OrderedDict()
    subcategories[AUTOMATION_ENTITY_IDS] = _lookup_automation_id
    subcategories[ENTITY_LABEL_IDS] = _lookup_automation_label
    subcategories[SUBCAT_ALL] = lookup_all

    return compile_policy(policy, subcategories, perm_lookup)
