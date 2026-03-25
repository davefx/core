"""Entity permissions."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable

import voluptuous as vol

from .const import (
    ENTITY_LABEL_IDS,
    POLICY_CONTROL,
    POLICY_EDIT,
    POLICY_READ,
    SUBCAT_ALL,
)
from .models import PermissionLookup
from .types import CategoryType, SubCategoryDict, ValueType
from .util import SubCatLookupType, compile_policy, lookup_all

SINGLE_ENTITY_SCHEMA = vol.Any(
    True,
    False,
    vol.Schema(
        {
            vol.Optional(POLICY_READ): vol.Any(True, False),
            vol.Optional(POLICY_CONTROL): vol.Any(True, False),
            vol.Optional(POLICY_EDIT): vol.Any(True, False),
            vol.Optional(SUBCAT_ALL): vol.Any(True, False),
        }
    ),
)

ENTITY_DOMAINS = "domains"
ENTITY_AREAS = "area_ids"
ENTITY_DEVICE_IDS = "device_ids"
ENTITY_ENTITY_IDS = "entity_ids"

ENTITY_VALUES_SCHEMA = vol.Any(True, False, vol.Schema({str: SINGLE_ENTITY_SCHEMA}))

ENTITY_POLICY_SCHEMA = vol.Any(
    True,
    False,
    vol.Schema(
        {
            vol.Optional(SUBCAT_ALL): SINGLE_ENTITY_SCHEMA,
            vol.Optional(ENTITY_AREAS): ENTITY_VALUES_SCHEMA,
            vol.Optional(ENTITY_DEVICE_IDS): ENTITY_VALUES_SCHEMA,
            vol.Optional(ENTITY_DOMAINS): ENTITY_VALUES_SCHEMA,
            vol.Optional(ENTITY_ENTITY_IDS): ENTITY_VALUES_SCHEMA,
            vol.Optional(ENTITY_LABEL_IDS): ENTITY_VALUES_SCHEMA,
        }
    ),
)


def _lookup_domain(
    perm_lookup: PermissionLookup, domains_dict: SubCategoryDict, entity_id: str
) -> ValueType | None:
    """Look up entity permissions by domain."""
    return domains_dict.get(entity_id.partition(".")[0])


def _lookup_area(
    perm_lookup: PermissionLookup, area_dict: SubCategoryDict, entity_id: str
) -> ValueType | None:
    """Look up entity permissions by area."""
    entity_entry = perm_lookup.entity_registry.async_get(entity_id)

    if entity_entry is None or entity_entry.device_id is None:
        return None

    device_entry = perm_lookup.device_registry.async_get(entity_entry.device_id)

    if device_entry is None or device_entry.area_id is None:
        return None

    return area_dict.get(device_entry.area_id)


def _lookup_device(
    perm_lookup: PermissionLookup, devices_dict: SubCategoryDict, entity_id: str
) -> ValueType | None:
    """Look up entity permissions by device."""
    entity_entry = perm_lookup.entity_registry.async_get(entity_id)

    if entity_entry is None or entity_entry.device_id is None:
        return None

    return devices_dict.get(entity_entry.device_id)


def _lookup_entity_id(
    perm_lookup: PermissionLookup, entities_dict: SubCategoryDict, entity_id: str
) -> ValueType | None:
    """Look up entity permission by entity id."""
    return entities_dict.get(entity_id)


def _lookup_label(
    perm_lookup: PermissionLookup, labels_dict: SubCategoryDict, entity_id: str
) -> ValueType | None:
    """Look up entity permissions by label.

    An entity can have multiple labels. Permissions from all matching
    labels are merged with deny-overrides-allow semantics: if any label
    denies a specific permission, it is denied regardless of other labels.
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

    # If any match is False (deny all), deny wins
    if any(perm is False for perm in matching):
        return False

    # If any match is True (allow all) and no deny, True wins
    if any(perm is True for perm in matching):
        return True

    # All matches are dicts — merge with deny-overrides-allow per key
    merged: dict[str, bool] = {}
    for perm in matching:
        assert isinstance(perm, dict)
        for key, value in perm.items():
            if key not in merged:
                merged[key] = value
            elif value is False:
                merged[key] = False  # deny always wins

    return merged or None


def compile_entities(
    policy: CategoryType, perm_lookup: PermissionLookup
) -> Callable[[str, str], bool]:
    """Compile policy into a function that tests policy."""
    subcategories: SubCatLookupType = OrderedDict()
    subcategories[ENTITY_ENTITY_IDS] = _lookup_entity_id
    subcategories[ENTITY_DEVICE_IDS] = _lookup_device
    subcategories[ENTITY_AREAS] = _lookup_area
    subcategories[ENTITY_LABEL_IDS] = _lookup_label
    subcategories[ENTITY_DOMAINS] = _lookup_domain
    subcategories[SUBCAT_ALL] = lookup_all

    return compile_policy(policy, subcategories, perm_lookup)
