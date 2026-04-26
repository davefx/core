"""ACL rule management for Home Assistant."""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.util import dt as dt_util

from ..permissions.merge import merge_policies
from ..permissions.types import PolicyType
from .conditions import evaluate_conditions
from .models import ACLRule
from .store import ACLStore


class ACLManager:
    """Manage ACL rules and compile them into group policies.

    ACL rules are compiled into a policy dict and merged with the
    group's base policy. The base policy is the policy that was set
    when the group was created or last updated directly (not via rules).
    """

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the ACL manager."""
        self.hass = hass
        self._store = ACLStore(hass)
        self._base_policies: dict[str, PolicyType] = {}

    async def async_load(self) -> None:
        """Load ACL data."""
        await self._store.async_load()
        # Restore base policies from persistent store
        self._base_policies = dict(self._store._base_policies)  # noqa: SLF001

    def async_get_rules(self, role_id: str | None = None) -> list[ACLRule]:
        """Get rules, optionally filtered by role."""
        return self._store.async_get_rules(role_id)

    def async_get_rule(self, rule_id: str) -> ACLRule | None:
        """Get a specific rule."""
        return self._store.async_get_rule(rule_id)

    async def async_create_rule(
        self,
        role_id: str,
        category: str,
        target_type: str,
        target_id: str | None,
        permission: str,
        effect: str,
        priority: int = 0,
        conditions: dict | None = None,
    ) -> ACLRule:
        """Create a new ACL rule and update the group's policy."""
        rule = ACLRule(
            role_id=role_id,
            category=category,
            target_type=target_type,
            target_id=target_id,
            permission=permission,
            effect=effect,
            priority=priority,
            conditions=conditions,
        )
        self._store.async_create_rule(rule)
        await self._async_compile_and_update_group(role_id)
        return rule

    async def async_update_rule(
        self,
        rule_id: str,
        **kwargs: Any,
    ) -> ACLRule | None:
        """Update an existing ACL rule."""
        rule = self._store.async_get_rule(rule_id)
        if rule is None:
            return None

        old_role_id = rule.role_id

        for attr in (
            "category",
            "target_type",
            "target_id",
            "permission",
            "effect",
            "priority",
            "conditions",
        ):
            if attr in kwargs:
                setattr(rule, attr, kwargs[attr])

        rule.modified_at = dt_util.utcnow()
        self._store.async_update_rule(rule)
        await self._async_compile_and_update_group(rule.role_id)

        # If role changed, also recompile the old role
        if old_role_id != rule.role_id:
            await self._async_compile_and_update_group(old_role_id)

        return rule

    async def async_delete_rule(self, rule_id: str) -> bool:
        """Delete an ACL rule."""
        rule = self._store.async_get_rule(rule_id)
        if rule is None:
            return False

        role_id = rule.role_id
        self._store.async_delete_rule(rule_id)
        await self._async_compile_and_update_group(role_id)
        return True

    @callback
    def compile_rules_to_policy(self, role_id: str) -> PolicyType:
        """Compile all rules for a role into a PolicyType dict.

        Rules are grouped by category, then by target_type, then by target_id.
        The resulting PolicyType can be used directly as a group's policy.
        """
        all_rules = self._store.async_get_rules(role_id)
        if not all_rules:
            return {}

        # Filter out rules whose conditions are not currently met
        rules = [
            r for r in all_rules if evaluate_conditions(r.conditions)
        ]
        if not rules:
            return {}

        # Sort by priority (lower = higher priority, processed first)
        rules.sort(key=lambda r: r.priority)

        policy: dict[str, Any] = {}

        for rule in rules:
            category = rule.category
            target_type = rule.target_type
            target_id = rule.target_id
            permission = rule.permission
            value = rule.effect == "allow"

            if category not in policy:
                policy[category] = {}

            cat_policy = policy[category]

            if target_type == "all":
                # Set permission on the "all" subcategory
                if "all" not in cat_policy:
                    cat_policy["all"] = {}
                if isinstance(cat_policy["all"], dict):
                    cat_policy["all"][permission] = value
            elif target_id is not None:
                if target_type not in cat_policy:
                    cat_policy[target_type] = {}
                target_dict = cat_policy[target_type]
                if isinstance(target_dict, dict):
                    if target_id not in target_dict:
                        target_dict[target_id] = {}
                    target_entry = target_dict[target_id]
                    if isinstance(target_entry, dict):
                        target_entry[permission] = value

        return policy

    @callback
    def get_effective_permissions(self, user_id: str) -> dict[str, Any]:
        """Get effective permissions for a user, combining all group policies.

        Useful for debugging: shows the compiled result after merging all
        group policies for the user.
        """
        from ..permissions import merge_policies

        auth = self.hass.auth  # type: ignore[attr-defined]
        # We can't await here since this is a callback, so we access
        # the store directly
        user = auth._store._users.get(user_id)  # noqa: SLF001
        if user is None:
            return {}

        policies = [group.policy for group in user.groups if group.policy]
        if not policies:
            return {}

        return dict(merge_policies(policies))

    def save_base_policy(self, role_id: str, policy: PolicyType) -> None:
        """Save the base policy for a group.

        Called when a group's policy is set directly (not via rules).
        This preserves the base so that rule compilation can merge on top.
        """
        self._base_policies[role_id] = dict(policy)
        self._store.async_save_base_policy(role_id, dict(policy))

    async def _async_compile_and_update_group(self, role_id: str) -> None:
        """Compile rules for a role and merge with the base policy."""
        auth = self.hass.auth  # type: ignore[attr-defined]
        group = await auth.async_get_group(role_id)
        if group is None or group.system_generated:
            return

        rules_policy = self.compile_rules_to_policy(role_id)

        # Get the base policy (saved when the group was created/updated)
        base = self._base_policies.get(role_id, {})

        if rules_policy and base:
            # Merge: rules on top of base policy
            merged = merge_policies([base, rules_policy])
        elif rules_policy:
            merged = rules_policy
        else:
            merged = base

        await auth.async_update_group(group, policy=merged)
