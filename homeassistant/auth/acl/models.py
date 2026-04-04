"""Models for ACL rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
import uuid

from homeassistant.util import dt as dt_util


@dataclass(slots=True)
class ACLRule:
    """An ACL rule that maps to a permission entry in a group policy."""

    role_id: str
    category: str  # "entities", "services", "automations"
    target_type: str  # "entity_ids", "device_ids", "area_ids", "label_ids", "domains", "service_ids", "all"
    target_id: str | None  # e.g., "light.kitchen", "light", "my-label"; None for "all"
    permission: str  # "read", "control", "edit", "trigger"
    effect: Literal["allow", "deny"]
    priority: int = 0  # lower = higher priority
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = field(default_factory=dt_util.utcnow)
    modified_at: datetime = field(default_factory=dt_util.utcnow)

    def to_dict(self) -> dict:
        """Serialize to dict for storage."""
        return {
            "id": self.id,
            "role_id": self.role_id,
            "category": self.category,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "permission": self.permission,
            "effect": self.effect,
            "priority": self.priority,
            "created_at": self.created_at.isoformat(),
            "modified_at": self.modified_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> ACLRule:
        """Deserialize from storage dict."""
        return cls(
            id=data["id"],
            role_id=data["role_id"],
            category=data["category"],
            target_type=data["target_type"],
            target_id=data.get("target_id"),
            permission=data["permission"],
            effect=data["effect"],
            priority=data.get("priority", 0),
            created_at=dt_util.parse_datetime(data["created_at"]) or dt_util.utcnow(),
            modified_at=dt_util.parse_datetime(data["modified_at"]) or dt_util.utcnow(),
        )
