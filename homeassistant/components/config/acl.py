"""Offer API to configure Home Assistant ACL rules."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant.auth.acl import ACLManager
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback

ACL_MANAGER_KEY = "acl_manager"


@callback
def async_setup(hass: HomeAssistant) -> bool:
    """Set up the ACL config API."""
    websocket_api.async_register_command(hass, websocket_acl_rules_list)
    websocket_api.async_register_command(hass, websocket_acl_rules_create)
    websocket_api.async_register_command(hass, websocket_acl_rules_update)
    websocket_api.async_register_command(hass, websocket_acl_rules_delete)
    websocket_api.async_register_command(hass, websocket_acl_effective_permissions)
    return True


def _get_acl_manager(hass: HomeAssistant) -> ACLManager:
    """Get or create the ACL manager."""
    if ACL_MANAGER_KEY not in hass.data:
        manager = ACLManager(hass)
        hass.data[ACL_MANAGER_KEY] = manager
    return hass.data[ACL_MANAGER_KEY]


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


@websocket_api.require_admin
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
    manager = _get_acl_manager(hass)
    await manager.async_load()

    rule = await manager.async_create_rule(
        role_id=msg["role_id"],
        category=msg["category"],
        target_type=msg["target_type"],
        target_id=msg.get("target_id"),
        permission=msg["permission"],
        effect=msg["effect"],
        priority=msg.get("priority", 0),
    )
    connection.send_message(
        websocket_api.result_message(msg["id"], {"rule": rule.to_dict()})
    )


@websocket_api.require_admin
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

    rule = await manager.async_update_rule(rule_id, **msg)
    if rule is None:
        connection.send_message(
            websocket_api.error_message(
                msg_id, websocket_api.ERR_NOT_FOUND, "Rule not found"
            )
        )
        return

    connection.send_message(
        websocket_api.result_message(msg_id, {"rule": rule.to_dict()})
    )


@websocket_api.require_admin
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

    if not await manager.async_delete_rule(msg["rule_id"]):
        connection.send_message(
            websocket_api.error_message(
                msg["id"], websocket_api.ERR_NOT_FOUND, "Rule not found"
            )
        )
        return

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
