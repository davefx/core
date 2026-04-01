"""Permissions for Home Assistant."""

from __future__ import annotations

from collections.abc import Callable

import voluptuous as vol

from .automations import AUTOMATION_POLICY_SCHEMA, compile_automations
from .const import CAT_AUTOMATIONS, CAT_ENTITIES, CAT_SERVICES
from .entities import ENTITY_POLICY_SCHEMA, compile_entities
from .merge import merge_policies
from .models import PermissionLookup
from .services import SERVICE_POLICY_SCHEMA, compile_services
from .types import PolicyType
from .util import test_all

POLICY_SCHEMA = vol.Schema(
    {
        vol.Optional(CAT_ENTITIES): ENTITY_POLICY_SCHEMA,
        vol.Optional(CAT_SERVICES): SERVICE_POLICY_SCHEMA,
        vol.Optional(CAT_AUTOMATIONS): AUTOMATION_POLICY_SCHEMA,
    }
)

__all__ = [
    "POLICY_SCHEMA",
    "AbstractPermissions",
    "OwnerPermissions",
    "PermissionLookup",
    "PolicyPermissions",
    "PolicyType",
    "merge_policies",
]


class AbstractPermissions:
    """Default permissions class."""

    _cached_entity_func: Callable[[str, str], bool] | None = None
    _cached_service_func: Callable[[str, str], bool] | None = None
    _cached_automation_func: Callable[[str, str], bool] | None = None

    def _entity_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test entity access."""
        raise NotImplementedError

    def _service_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test service access."""
        raise NotImplementedError

    def _automation_func(self) -> Callable[[str, str], bool]:
        """Return a function that can test automation access."""
        raise NotImplementedError

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


OwnerPermissions = _OwnerPermissions()
