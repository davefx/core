"""Storage for ACL rules."""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.storage import Store

from .models import ACLRule

STORAGE_VERSION = 1
STORAGE_KEY = "core.acl"
DEFAULT_SAVE_DELAY = 1


class ACLStore:
    """Store ACL rules persistently."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the ACL store."""
        self.hass = hass
        self._rules: dict[str, ACLRule] = {}
        self._store = Store[dict[str, Any]](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self._loaded = False

    async def async_load(self) -> None:
        """Load rules from disk."""
        if self._loaded:
            return

        self._loaded = True
        data = await self._store.async_load()

        if data is None:
            return

        for rule_dict in data.get("rules", []):
            rule = ACLRule.from_dict(rule_dict)
            self._rules[rule.id] = rule

    @callback
    def async_get_rules(self, role_id: str | None = None) -> list[ACLRule]:
        """Get all rules, optionally filtered by role."""
        if role_id is not None:
            return [r for r in self._rules.values() if r.role_id == role_id]
        return list(self._rules.values())

    @callback
    def async_get_rule(self, rule_id: str) -> ACLRule | None:
        """Get a specific rule by ID."""
        return self._rules.get(rule_id)

    @callback
    def async_create_rule(self, rule: ACLRule) -> None:
        """Add a new rule."""
        self._rules[rule.id] = rule
        self._async_schedule_save()

    @callback
    def async_update_rule(self, rule: ACLRule) -> None:
        """Update an existing rule."""
        self._rules[rule.id] = rule
        self._async_schedule_save()

    @callback
    def async_delete_rule(self, rule_id: str) -> bool:
        """Delete a rule by ID. Returns True if deleted."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            self._async_schedule_save()
            return True
        return False

    @callback
    def _async_schedule_save(self) -> None:
        """Schedule a save."""
        self._store.async_delay_save(self._data_to_save, DEFAULT_SAVE_DELAY)

    @callback
    def _data_to_save(self) -> dict[str, Any]:
        """Return the data to store."""
        return {
            "rules": [rule.to_dict() for rule in self._rules.values()],
        }
