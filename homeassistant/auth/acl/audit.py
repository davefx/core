"""Audit logging for ACL permission checks and admin actions."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any
import uuid

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

STORAGE_VERSION = 1
STORAGE_KEY = "core.acl_audit"
DEFAULT_MAX_ENTRIES = 10000
SAVE_INTERVAL = 60  # seconds


class AuditAction(StrEnum):
    """Audit action types."""

    PERMISSION_DENIED = "permission_denied"
    ROLE_CREATED = "role_created"
    ROLE_UPDATED = "role_updated"
    ROLE_DELETED = "role_deleted"
    RULE_CREATED = "rule_created"
    RULE_UPDATED = "rule_updated"
    RULE_DELETED = "rule_deleted"
    USER_GROUP_CHANGED = "user_group_changed"


class AuditLevel(StrEnum):
    """Audit logging level."""

    ALL = "all"
    DENIALS_ONLY = "denials_only"
    ADMIN_ACTIONS_ONLY = "admin_actions_only"
    NONE = "none"


@dataclass(slots=True)
class AuditEntry:
    """A single audit log entry."""

    action: str
    user_id: str | None = None
    category: str | None = None
    target: str | None = None
    permission: str | None = None
    result: str | None = None
    context: dict[str, Any] | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = field(default_factory=dt_util.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "user_id": self.user_id,
            "category": self.category,
            "target": self.target,
            "permission": self.permission,
            "result": self.result,
            "context": self.context,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        """Deserialize from dict."""
        return cls(
            id=data["id"],
            timestamp=dt_util.parse_datetime(data["timestamp"]) or dt_util.utcnow(),
            action=data["action"],
            user_id=data.get("user_id"),
            category=data.get("category"),
            target=data.get("target"),
            permission=data.get("permission"),
            result=data.get("result"),
            context=data.get("context"),
        )


class AuditLogger:
    """Audit logger with ring buffer and periodic persistence."""

    def __init__(
        self,
        hass: HomeAssistant,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        level: AuditLevel = AuditLevel.DENIALS_ONLY,
    ) -> None:
        """Initialize the audit logger."""
        self.hass = hass
        self._entries: deque[AuditEntry] = deque(maxlen=max_entries)
        self._level = level
        self._store = Store[dict[str, Any]](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True
        )
        self._loaded = False

    @property
    def level(self) -> AuditLevel:
        """Get current audit level."""
        return self._level

    @level.setter
    def level(self, value: AuditLevel) -> None:
        """Set audit level."""
        self._level = value

    async def async_load(self) -> None:
        """Load audit log from disk."""
        if self._loaded:
            return

        self._loaded = True
        data = await self._store.async_load()

        if data is None:
            return

        for entry_dict in data.get("entries", []):
            self._entries.append(AuditEntry.from_dict(entry_dict))

    @callback
    def log_denial(
        self,
        user_id: str | None,
        category: str | None,
        target: str | None,
        permission: str | None,
    ) -> None:
        """Log a permission denial."""
        if self._level == AuditLevel.NONE:
            return
        if self._level == AuditLevel.ADMIN_ACTIONS_ONLY:
            return

        entry = AuditEntry(
            action=AuditAction.PERMISSION_DENIED,
            user_id=user_id,
            category=category,
            target=target,
            permission=permission,
            result="denied",
        )
        self._entries.append(entry)
        self.hass.bus.async_fire("acl_audit_entry", entry.to_dict())
        self._async_schedule_save()

    @callback
    def log_admin_action(
        self,
        action: str,
        user_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Log an admin action (role/rule CRUD)."""
        if self._level == AuditLevel.NONE:
            return
        if self._level == AuditLevel.DENIALS_ONLY:
            return

        entry = AuditEntry(
            action=action,
            user_id=user_id,
            context=context,
        )
        self._entries.append(entry)
        self.hass.bus.async_fire("acl_audit_entry", entry.to_dict())
        self._async_schedule_save()

    @callback
    def get_entries(
        self,
        user_id: str | None = None,
        action: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Get audit entries with optional filtering."""
        entries = list(self._entries)

        if user_id is not None:
            entries = [e for e in entries if e.user_id == user_id]

        if action is not None:
            entries = [e for e in entries if e.action == action]

        # Most recent first
        entries.reverse()

        if limit is not None:
            entries = entries[:limit]

        return [e.to_dict() for e in entries]

    @callback
    def clear(self) -> None:
        """Clear all audit entries."""
        self._entries.clear()
        self._async_schedule_save()

    @callback
    def _async_schedule_save(self) -> None:
        """Schedule a save."""
        self._store.async_delay_save(self._data_to_save, SAVE_INTERVAL)

    @callback
    def _data_to_save(self) -> dict[str, Any]:
        """Return data to persist."""
        return {
            "entries": [e.to_dict() for e in self._entries],
        }
