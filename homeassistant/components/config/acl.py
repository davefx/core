"""Offer API to configure Home Assistant ACL rules."""

from typing import Any

import voluptuous as vol

from homeassistant.auth.acl import ACLManager
from homeassistant.auth.acl.audit import AuditAction, AuditLogger
from homeassistant.auth.models import User
from homeassistant.auth.permissions import can_grant, can_modify_group
from homeassistant.auth.permissions.types import PolicyType
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.start import async_at_started

ACL_MANAGER_KEY = "acl_manager"
AUDIT_LOGGER_KEY = "acl_audit_logger"


@callback
def async_setup(hass: HomeAssistant) -> bool:
    """Set up the ACL config API."""
    websocket_api.async_register_command(hass, websocket_acl_rules_list)
    websocket_api.async_register_command(hass, websocket_acl_rules_create)
    websocket_api.async_register_command(hass, websocket_acl_rules_update)
    websocket_api.async_register_command(hass, websocket_acl_rules_delete)
    websocket_api.async_register_command(hass, websocket_acl_effective_permissions)
    websocket_api.async_register_command(hass, websocket_acl_audit_list)
    websocket_api.async_register_command(hass, websocket_acl_audit_clear)

    async def _async_load_manager(hass: HomeAssistant) -> None:
        """Load the ACL manager at startup so time-window rules track live.

        The manager's periodic recompile (for time-window conditions) only runs
        once it is loaded; loading here means it does not depend on an admin
        opening the ACL panel.
        """
        await _get_acl_manager(hass).async_load()

    async_at_started(hass, _async_load_manager)
    return True


def _get_acl_manager(hass: HomeAssistant) -> ACLManager:
    """Get or create the ACL manager."""
    if ACL_MANAGER_KEY not in hass.data:
        manager = ACLManager(hass)
        hass.data[ACL_MANAGER_KEY] = manager
    return hass.data[ACL_MANAGER_KEY]


def _get_audit_logger(hass: HomeAssistant) -> AuditLogger:
    """Get or create the audit logger."""
    if AUDIT_LOGGER_KEY not in hass.data:
        logger = AuditLogger(hass)
        hass.data[AUDIT_LOGGER_KEY] = logger
    return hass.data[AUDIT_LOGGER_KEY]


def _rule_to_policy(
    category: str, target_type: str, target_id: str | None, permission: str, effect: str
) -> PolicyType:
    """Build the policy fragment a single rule contributes.

    Mirrors ACLManager.compile_rules_to_policy for one rule, so the escalation
    guard (can_grant) can decide whether the caller has authority over exactly
    the permission this rule sets — in either direction (allow or deny).
    """
    allow = effect == "allow"
    if target_type == "all":
        return {category: {"all": {permission: allow}}}
    return {category: {target_type: {target_id: {permission: allow}}}}


async def _role_members(hass: HomeAssistant, role_id: str) -> list[User]:
    """Return the users who belong to a role (group)."""
    users = await hass.auth.async_get_users()
    return [user for user in users if any(g.id == role_id for g in user.groups)]


async def _authorize_rule_change(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg_id: int,
    role_id: str,
    *policies: PolicyType,
) -> bool:
    """Whether the caller may create/update/delete a rule on `role_id`.

    Changing ACL rules changes the authorization policy itself, so this is
    deliberately strict. The owner always may. Any other caller must:

    * not be a member of the target role — otherwise they could rewrite the
      very rules that restrict them (the reason rule edits were owner-only,
      and the one path an admin could use to escape a deny);
    * be able to modify the role group: hold its `manage` scope AND strictly
      dominate every member (no restricting a peer or superior); and
    * have authority (can_grant) over every permission the change touches —
      both the rule being removed and the one being written — so they can
      neither escalate access they lack nor sabotage a scope they don't hold.
    """
    user = connection.user
    if user.is_owner:
        return True

    members = await _role_members(hass, role_id)
    authorized = (
        not any(member.id == user.id for member in members)
        and can_modify_group(user, role_id, members)
        and all(can_grant(user, policy) for policy in policies)
    )
    if not authorized:
        connection.send_message(
            websocket_api.error_message(
                msg_id,
                websocket_api.ERR_UNAUTHORIZED,
                "Not authorized to modify ACL rules for this role",
            )
        )
    return authorized


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/acl/rules/list",
        vol.Optional("role_id"): str,
    }
)
@websocket_api.async_response
async def websocket_acl_rules_list(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """List ACL rules."""
    manager = _get_acl_manager(hass)
    await manager.async_load()
    rules = manager.async_get_rules(role_id=msg.get("role_id"))
    connection.send_message(
        websocket_api.result_message(
            msg["id"], [rule.to_dict() for rule in rules]
        )
    )


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/acl/rules/create",
        vol.Required("role_id"): str,
        vol.Required("category"): vol.In(["entities", "services", "automations"]),
        vol.Required("target_type"): vol.In(
            [
                "entity_ids",
                "device_ids",
                "area_ids",
                "label_ids",
                "domains",
                "service_ids",
                "all",
            ]
        ),
        vol.Optional("target_id"): str,
        vol.Required("permission"): vol.In(
            ["read", "control", "edit", "trigger", "manage"]
        ),
        vol.Required("effect"): vol.In(["allow", "deny"]),
        vol.Optional("priority", default=0): int,
    }
)
@websocket_api.async_response
async def websocket_acl_rules_create(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Create an ACL rule."""
    rule_policy = _rule_to_policy(
        msg["category"],
        msg["target_type"],
        msg.get("target_id"),
        msg["permission"],
        msg["effect"],
    )
    if not await _authorize_rule_change(
        hass, connection, msg["id"], msg["role_id"], rule_policy
    ):
        return
    manager = _get_acl_manager(hass)
    await manager.async_load()

    try:
        rule = await manager.async_create_rule(
            role_id=msg["role_id"],
            category=msg["category"],
            target_type=msg["target_type"],
            target_id=msg.get("target_id"),
            permission=msg["permission"],
            effect=msg["effect"],
            priority=msg.get("priority", 0),
            conditions=msg.get("conditions"),
        )
    except ValueError as err:
        connection.send_message(
            websocket_api.error_message(
                msg["id"], websocket_api.ERR_INVALID_FORMAT, str(err)
            )
        )
        return

    logger = _get_audit_logger(hass)
    await logger.async_load()
    logger.log_admin_action(
        AuditAction.RULE_CREATED,
        user_id=connection.user.id,
        context={"rule_id": rule.id, "role_id": rule.role_id},
    )

    connection.send_message(
        websocket_api.result_message(msg["id"], {"rule": rule.to_dict()})
    )


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/acl/rules/update",
        vol.Required("rule_id"): str,
        vol.Optional("category"): vol.In(["entities", "services", "automations"]),
        vol.Optional("target_type"): vol.In(
            [
                "entity_ids",
                "device_ids",
                "area_ids",
                "label_ids",
                "domains",
                "service_ids",
                "all",
            ]
        ),
        vol.Optional("target_id"): str,
        vol.Optional("permission"): vol.In(
            ["read", "control", "edit", "trigger", "manage"]
        ),
        vol.Optional("effect"): vol.In(["allow", "deny"]),
        vol.Optional("priority"): int,
    }
)
@websocket_api.async_response
async def websocket_acl_rules_update(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Update an ACL rule."""
    manager = _get_acl_manager(hass)
    await manager.async_load()

    msg_id = msg.pop("id")
    msg.pop("type")
    rule_id = msg.pop("rule_id")

    existing = manager.async_get_rule(rule_id)
    if existing is None:
        connection.send_message(
            websocket_api.error_message(
                msg_id, websocket_api.ERR_NOT_FOUND, "Rule not found"
            )
        )
        return

    # Authorize over both the scope being changed away from and the new scope,
    # so the caller can't pivot a rule onto a permission they have no authority
    # over. role_id is immutable via this endpoint, so it comes from the rule.
    old_policy = _rule_to_policy(
        existing.category,
        existing.target_type,
        existing.target_id,
        existing.permission,
        existing.effect,
    )
    new_policy = _rule_to_policy(
        msg.get("category", existing.category),
        msg.get("target_type", existing.target_type),
        msg.get("target_id", existing.target_id),
        msg.get("permission", existing.permission),
        msg.get("effect", existing.effect),
    )
    if not await _authorize_rule_change(
        hass, connection, msg_id, existing.role_id, old_policy, new_policy
    ):
        return

    try:
        rule = await manager.async_update_rule(rule_id, **msg)
    except ValueError as err:
        connection.send_message(
            websocket_api.error_message(
                msg_id, websocket_api.ERR_INVALID_FORMAT, str(err)
            )
        )
        return
    if rule is None:
        connection.send_message(
            websocket_api.error_message(
                msg_id, websocket_api.ERR_NOT_FOUND, "Rule not found"
            )
        )
        return

    logger = _get_audit_logger(hass)
    await logger.async_load()
    logger.log_admin_action(
        AuditAction.RULE_UPDATED,
        user_id=connection.user.id,
        context={"rule_id": rule.id, "role_id": rule.role_id},
    )

    connection.send_message(
        websocket_api.result_message(msg_id, {"rule": rule.to_dict()})
    )


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/acl/rules/delete",
        vol.Required("rule_id"): str,
    }
)
@websocket_api.async_response
async def websocket_acl_rules_delete(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Delete an ACL rule."""
    manager = _get_acl_manager(hass)
    await manager.async_load()

    existing = manager.async_get_rule(msg["rule_id"])
    if existing is None:
        connection.send_message(
            websocket_api.error_message(
                msg["id"], websocket_api.ERR_NOT_FOUND, "Rule not found"
            )
        )
        return

    # Removing a rule changes the role's effective policy too, so it needs the
    # same authority over the scope the rule touches.
    rule_policy = _rule_to_policy(
        existing.category,
        existing.target_type,
        existing.target_id,
        existing.permission,
        existing.effect,
    )
    if not await _authorize_rule_change(
        hass, connection, msg["id"], existing.role_id, rule_policy
    ):
        return

    if not await manager.async_delete_rule(msg["rule_id"]):
        connection.send_message(
            websocket_api.error_message(
                msg["id"], websocket_api.ERR_NOT_FOUND, "Rule not found"
            )
        )
        return

    logger = _get_audit_logger(hass)
    await logger.async_load()
    logger.log_admin_action(
        AuditAction.RULE_DELETED,
        user_id=connection.user.id,
        context={"rule_id": msg["rule_id"]},
    )

    connection.send_message(websocket_api.result_message(msg["id"]))


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/acl/effective_permissions",
        vol.Required("user_id"): str,
    }
)
@websocket_api.async_response
async def websocket_acl_effective_permissions(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Get effective permissions for a user (debugging)."""
    manager = _get_acl_manager(hass)
    await manager.async_load()

    permissions = manager.get_effective_permissions(msg["user_id"])
    connection.send_message(
        websocket_api.result_message(msg["id"], permissions)
    )


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/acl/audit/list",
        vol.Optional("user_id"): str,
        vol.Optional("action"): str,
        vol.Optional("limit"): vol.All(int, vol.Range(min=1, max=10000)),
    }
)
@websocket_api.async_response
async def websocket_acl_audit_list(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Query audit log entries."""
    logger = _get_audit_logger(hass)
    await logger.async_load()

    entries = logger.get_entries(
        user_id=msg.get("user_id"),
        action=msg.get("action"),
        limit=msg.get("limit"),
    )
    connection.send_message(
        websocket_api.result_message(msg["id"], entries)
    )


@websocket_api.require_admin
@websocket_api.websocket_command(
    {vol.Required("type"): "config/acl/audit/clear"}
)
@websocket_api.async_response
async def websocket_acl_audit_clear(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Clear the audit log (owner only)."""
    if not connection.user.is_owner:
        connection.send_message(
            websocket_api.error_message(
                msg["id"], "not_owner", "Only the owner can clear the audit log"
            )
        )
        return

    logger = _get_audit_logger(hass)
    logger.clear()
    connection.send_message(websocket_api.result_message(msg["id"]))
