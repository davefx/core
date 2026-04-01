"""Service permissions."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable

import voluptuous as vol

from .const import POLICY_CONTROL, POLICY_READ, SUBCAT_ALL
from .models import PermissionLookup
from .types import CategoryType, SubCategoryDict, ValueType
from .util import SubCatLookupType, compile_policy, lookup_all

SINGLE_SERVICE_SCHEMA = vol.Any(
    True,
    False,
    vol.Schema(
        {
            vol.Optional(POLICY_READ): vol.Any(True, False),
            vol.Optional(POLICY_CONTROL): vol.Any(True, False),
            vol.Optional(SUBCAT_ALL): vol.Any(True, False),
        }
    ),
)

SERVICE_SERVICE_IDS = "service_ids"
SERVICE_DOMAINS = "domains"

SERVICE_VALUES_SCHEMA = vol.Any(True, False, vol.Schema({str: SINGLE_SERVICE_SCHEMA}))

SERVICE_POLICY_SCHEMA = vol.Any(
    True,
    False,
    vol.Schema(
        {
            vol.Optional(SUBCAT_ALL): SINGLE_SERVICE_SCHEMA,
            vol.Optional(SERVICE_SERVICE_IDS): SERVICE_VALUES_SCHEMA,
            vol.Optional(SERVICE_DOMAINS): SERVICE_VALUES_SCHEMA,
        }
    ),
)


def _lookup_service_id(
    perm_lookup: PermissionLookup, services_dict: SubCategoryDict, service_name: str
) -> ValueType | None:
    """Look up service permission by full service name (domain.service)."""
    return services_dict.get(service_name)


def _lookup_service_domain(
    perm_lookup: PermissionLookup, domains_dict: SubCategoryDict, service_name: str
) -> ValueType | None:
    """Look up service permission by domain."""
    return domains_dict.get(service_name.partition(".")[0])


def compile_services(
    policy: CategoryType, perm_lookup: PermissionLookup
) -> Callable[[str, str], bool]:
    """Compile service policy into a function that tests permission.

    Service names are in the format "domain.service_name".
    """
    subcategories: SubCatLookupType = OrderedDict()
    subcategories[SERVICE_SERVICE_IDS] = _lookup_service_id
    subcategories[SERVICE_DOMAINS] = _lookup_service_domain
    subcategories[SUBCAT_ALL] = lookup_all

    return compile_policy(policy, subcategories, perm_lookup)
