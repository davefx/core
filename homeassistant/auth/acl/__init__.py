"""ACL rule management for Home Assistant."""

from datetime import datetime, timedelta
import logging
from typing import Any

import voluptuous as vol

from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.util import dt as dt_util

from ..permissions import POLICY_SCHEMA
from ..permissions.merge import merge_policies
from ..permissions.types import PolicyType
from .conditions import evaluate_conditions
from .models import ACLRule, validate_rule_shape
from .store import ACLStore

_LOGGER = logging.getLogger(__name__)

# Time-window conditions are minute-precision, so re-evaluate at that cadence.
TIME_RECOMPILE_INTERVAL = timedelta(minutes=1)


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
        self._unsub_time: CALLBACK_TYPE | None = None

    async def async_load(self) -> None:
        """Load ACL data."""
        await self._store.async_load()
        # Restore base policies from persistent store
        self._base_policies = dict(self._store._base_policies)  # noqa: SLF001
        self._async_setup_time_tracking()

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
        # Reject category/target_type/permission mismatches up front so a rule
        # that would compile to a silently-dead policy is never stored.
        validate_rule_shape(category, target_type, permission, effect)
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
        self._async_setup_time_tracking()
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

        # Validate the resulting shape (existing values overlaid with the
        # update) before mutating, so a partial update can't push the rule
        # into an invalid category/target_type/permission combination.
        validate_rule_shape(
            kwargs.get("category", rule.category),
            kwargs.get("target_type", rule.target_type),
            kwargs.get("permission", rule.permission),
            kwargs.get("effect", rule.effect),
        )

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

        self._async_setup_time_tracking()
        return rule

    async def async_delete_rule(self, rule_id: str) -> bool:
        """Delete an ACL rule."""
        rule = self._store.async_get_rule(rule_id)
        if rule is None:
            return False

        role_id = rule.role_id
        self._store.async_delete_rule(rule_id)
        await self._async_compile_and_update_group(role_id)
        self._async_setup_time_tracking()
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

        # Drop rules whose condition is not currently met. For an allow rule
        # this removes access (fail-closed); for a deny with a time_window it
        # means "deny only during the window", which is the intended model.
        # Malformed conditions are rejected at write/load time, so they cannot
        # reach here and silently drop a deny.
        rules = [r for r in all_rules if evaluate_conditions(r.conditions)]
        if not rules:
            return {}

        # Deterministic order; deny-overrides (below) makes the result
        # independent of order, so a deny can never be clobbered by an allow
        # on the same target+permission regardless of priority.
        rules.sort(key=lambda r: r.priority)

        def _apply(entry: dict[str, Any], perm: str, allow: bool) -> None:
            """Set a permission with deny-overrides: a deny always wins."""
            if entry.get(perm) is False:
                return
            entry[perm] = allow

        policy: dict[str, Any] = {}

        for rule in rules:
            category = rule.category
            target_type = rule.target_type
            target_id = rule.target_id
            permission = rule.permission
            allow = rule.effect == "allow"

            if category not in policy:
                policy[category] = {}

            cat_policy = policy[category]

            if target_type == "all":
                if "all" not in cat_policy:
                    cat_policy["all"] = {}
                if isinstance(cat_policy["all"], dict):
                    _apply(cat_policy["all"], permission, allow)
            elif target_id is not None:
                if target_type not in cat_policy:
                    cat_policy[target_type] = {}
                target_dict = cat_policy[target_type]
                if isinstance(target_dict, dict):
                    if target_id not in target_dict:
                        target_dict[target_id] = {}
                    target_entry = target_dict[target_id]
                    if isinstance(target_entry, dict):
                        _apply(target_entry, permission, allow)

        return policy

    @callback
    def get_effective_permissions(self, user_id: str) -> dict[str, Any]:
        """Get effective permissions for a user, combining all group policies.

        Useful for debugging: shows the compiled result after merging all
        group policies for the user.
        """
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

        # Never push a policy the permission engine can't represent. A rule
        # whose category/target_type/permission don't line up compiles into a
        # shape POLICY_SCHEMA rejects (and would otherwise be a silently-dead
        # restriction). Refuse rather than apply a broken policy.
        try:
            merged = POLICY_SCHEMA(merged)
        except vol.Invalid as err:
            _LOGGER.error(
                "Refusing to apply invalid compiled ACL policy for role %s: %s",
                role_id,
                err,
            )
            return

        # Skip the write when nothing changed. The periodic time-window
        # recompile calls this every minute, so guarding here avoids needless
        # persistence and permission-cache invalidation when no window flipped.
        if group.policy == merged:
            return

        await auth.async_update_group(group, policy=merged)

    @callback
    def _async_time_conditioned_roles(self) -> set[str]:
        """Return role IDs that have at least one time-window rule."""
        return {
            rule.role_id
            for rule in self._store.async_get_rules()
            if rule.conditions and rule.conditions.get("type") == "time_window"
        }

    @callback
    def _async_setup_time_tracking(self) -> None:
        """(Re)start the periodic recompile when time-window rules exist.

        Time-window conditions decide whether a rule is active *right now*, but
        the compiled group policy is a static snapshot. We re-evaluate it once a
        minute (windows are minute-precision) so a window opening or closing
        takes effect live, without an admin having to touch the rule. The timer
        only runs while at least one time-window rule exists.
        """
        if self._unsub_time is not None:
            self._unsub_time()
            self._unsub_time = None

        if not self._async_time_conditioned_roles():
            return

        self._unsub_time = async_track_time_interval(
            self.hass,
            self._async_recompile_time_conditioned_roles,
            TIME_RECOMPILE_INTERVAL,
        )

    async def _async_recompile_time_conditioned_roles(
        self, now: datetime | None = None
    ) -> None:
        """Recompile roles whose time-window conditions may have flipped."""
        for role_id in self._async_time_conditioned_roles():
            await self._async_compile_and_update_group(role_id)
