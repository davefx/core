"""Models for ACL rules."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
import uuid

from homeassistant.util import dt as dt_util

EFFECTS = ("allow", "deny")

# Which target_type / permission values the permission engine can actually
# represent for each category. A rule outside these sets compiles into a
# policy shape the engine ignores (a silently-dead restriction), so it is
# rejected at the API and dropped on load.
TARGET_TYPES_BY_CATEGORY: dict[str, set[str]] = {
    "entities": {"all", "entity_ids", "device_ids", "area_ids", "label_ids", "domains"},
    "services": {"all", "service_ids", "domains"},
    "automations": {"all", "entity_ids", "label_ids"},
}
PERMISSIONS_BY_CATEGORY: dict[str, set[str]] = {
    "entities": {"read", "control", "edit"},
    "services": {"read", "control"},
    "automations": {"read", "edit", "trigger"},
}


def validate_rule_shape(
    category: str, target_type: str, permission: str, effect: str
) -> None:
    """Raise ValueError if the category/target_type/permission/effect mismatch."""
    if category not in TARGET_TYPES_BY_CATEGORY:
        raise ValueError(f"invalid ACL category {category!r}")
    if effect not in EFFECTS:
        raise ValueError(f"invalid ACL effect {effect!r}")
    if target_type not in TARGET_TYPES_BY_CATEGORY[category]:
        raise ValueError(
            f"target_type {target_type!r} is not valid for category {category!r}"
        )
    if permission not in PERMISSIONS_BY_CATEGORY[category]:
        raise ValueError(
            f"permission {permission!r} is not valid for category {category!r}"
        )


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
    conditions: dict | None = None  # optional time-based conditions
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = field(default_factory=dt_util.utcnow)
    modified_at: datetime = field(default_factory=dt_util.utcnow)

    def to_dict(self) -> dict:
        """Serialize to dict for storage."""
        result = {
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
        if self.conditions is not None:
            result["conditions"] = self.conditions
        return result

    @classmethod
    def from_dict(cls, data: dict) -> ACLRule:
        """Deserialize from storage dict, rejecting semantically invalid rules."""
        validate_rule_shape(
            data["category"], data["target_type"], data["permission"], data["effect"]
        )
        conditions = data.get("conditions")
        if conditions is not None and not isinstance(conditions, dict):
            raise ValueError("ACL rule conditions must be a dict or null")
        return cls(
            id=data["id"],
            role_id=data["role_id"],
            category=data["category"],
            target_type=data["target_type"],
            target_id=data.get("target_id"),
            permission=data["permission"],
            effect=data["effect"],
            priority=data.get("priority", 0),
            conditions=conditions,
            created_at=dt_util.parse_datetime(data["created_at"]) or dt_util.utcnow(),
            modified_at=dt_util.parse_datetime(data["modified_at"]) or dt_util.utcnow(),
        )
