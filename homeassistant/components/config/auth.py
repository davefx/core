"""Offer API to configure Home Assistant auth."""

from typing import Any

import voluptuous as vol

from homeassistant.auth.models import User
from homeassistant.auth.permissions import (
    POLICY_SCHEMA,
    can_create_groups,
    can_grant,
    can_modify_group,
    can_set_member,
)
from homeassistant.components import websocket_api
from homeassistant.components.config.acl import ACL_MANAGER_KEY
from homeassistant.core import HomeAssistant, callback


async def _group_members(hass: HomeAssistant, group_id: str) -> list[User]:
    """Return the users who are members of a group."""
    users = await hass.auth.async_get_users()
    return [user for user in users if any(g.id == group_id for g in user.groups)]


@callback
def _send_unauthorized(
    connection: websocket_api.ActiveConnection, msg_id: int
) -> None:
    """Reject a management action the caller isn't authorized for."""
    connection.send_message(
        websocket_api.error_message(
            msg_id,
            websocket_api.ERR_UNAUTHORIZED,
            "Not authorized to manage this group",
        )
    )


async def _authorize_member_update(
    hass: HomeAssistant,
    caller: User,
    target: User,
    msg: dict[str, Any],
) -> bool:
    """Whether a non-admin caller may apply this `config/auth/update`.

    Delegated membership management: a non-admin may change only a user's
    `group_ids` (never account fields like name / is_active / local_only), and
    only for groups whose membership they control over a target they dominate.
    Adding to a group additionally requires authority over that group's policy,
    so a manager can't drop a user into a more-privileged group.
    """
    # Only group membership may be delegated; account fields stay admin-only.
    if any(field in msg for field in ("name", "is_active", "local_only")):
        return False
    if "group_ids" not in msg:
        return False

    current = {group.id for group in target.groups}
    requested = set(msg["group_ids"])
    changed = current ^ requested
    if not changed:
        return True

    for group_id in changed:
        if not can_set_member(caller, group_id, target):
            return False

    # Adds also require authority over the destination group's policy.
    for group_id in requested - current:
        group = await hass.auth.async_get_group(group_id)
        if group is None or not can_grant(caller, group.policy):
            return False

    return True


@callback
def async_setup(hass: HomeAssistant) -> bool:
    """Enable the Home Assistant views."""
    websocket_api.async_register_command(hass, websocket_list)
    websocket_api.async_register_command(hass, websocket_delete)
    websocket_api.async_register_command(hass, websocket_create)
    websocket_api.async_register_command(hass, websocket_update)
    websocket_api.async_register_command(hass, websocket_group_list)
    websocket_api.async_register_command(hass, websocket_group_create)
    websocket_api.async_register_command(hass, websocket_group_update)
    websocket_api.async_register_command(hass, websocket_group_delete)
    return True


@websocket_api.require_admin
@websocket_api.websocket_command({vol.Required("type"): "config/auth/list"})
@websocket_api.async_response
async def websocket_list(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Return a list of users."""
    result = [_user_info(u) for u in await hass.auth.async_get_users()]

    connection.send_message(websocket_api.result_message(msg["id"], result))


@websocket_api.require_admin
@websocket_api.websocket_command(
    {vol.Required("type"): "config/auth/delete", vol.Required("user_id"): str}
)
@websocket_api.async_response
async def websocket_delete(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Delete a user."""
    if msg["user_id"] == connection.user.id:
        connection.send_message(
            websocket_api.error_message(
                msg["id"], "no_delete_self", "Unable to delete your own account"
            )
        )
        return

    if not (user := await hass.auth.async_get_user(msg["user_id"])):
        connection.send_message(
            websocket_api.error_message(msg["id"], "not_found", "User not found")
        )
        return

    await hass.auth.async_remove_user(user)

    connection.send_message(websocket_api.result_message(msg["id"]))


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/auth/create",
        vol.Required("name"): str,
        vol.Optional("group_ids"): [str],
        vol.Optional("local_only"): bool,
    }
)
@websocket_api.async_response
async def websocket_create(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Create a user."""
    user = await hass.auth.async_create_user(
        msg["name"], group_ids=msg.get("group_ids"), local_only=msg.get("local_only")
    )

    connection.send_message(
        websocket_api.result_message(msg["id"], {"user": _user_info(user)})
    )


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/auth/update",
        vol.Required("user_id"): str,
        vol.Optional("name"): str,
        vol.Optional("is_active"): bool,
        vol.Optional("group_ids"): [str],
        vol.Optional("local_only"): bool,
    }
)
@websocket_api.async_response
async def websocket_update(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Update a user."""
    if not (user := await hass.auth.async_get_user(msg.pop("user_id"))):
        connection.send_message(
            websocket_api.error_message(
                msg["id"], websocket_api.ERR_NOT_FOUND, "User not found"
            )
        )
        return

    if user.system_generated:
        connection.send_message(
            websocket_api.error_message(
                msg["id"],
                "cannot_modify_system_generated",
                "Unable to update system generated users.",
            )
        )
        return

    if user.is_owner and msg.get("is_active") is False:
        connection.send_message(
            websocket_api.error_message(
                msg["id"],
                "cannot_deactivate_owner",
                "Unable to deactivate owner.",
            )
        )
        return

    if not connection.user.is_admin and not await _authorize_member_update(
        hass, connection.user, user, msg
    ):
        _send_unauthorized(connection, msg["id"])
        return

    msg.pop("type")
    msg_id = msg.pop("id")

    await hass.auth.async_update_user(user, **msg)

    connection.send_message(
        websocket_api.result_message(msg_id, {"user": _user_info(user)})
    )


@websocket_api.require_admin
@websocket_api.websocket_command(
    {vol.Required("type"): "config/auth/group/list"}
)
@websocket_api.async_response
async def websocket_group_list(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Return a list of groups."""
    groups = await hass.auth.async_get_groups()
    result = [_group_info(group) for group in groups]
    connection.send_message(websocket_api.result_message(msg["id"], result))


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/auth/group/create",
        vol.Required("name"): str,
        vol.Required("policy"): POLICY_SCHEMA,
    }
)
@websocket_api.async_response
async def websocket_group_create(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Create a custom group."""
    user = connection.user
    if not can_create_groups(user) or not can_grant(user, msg["policy"]):
        _send_unauthorized(connection, msg["id"])
        return
    group = await hass.auth.async_create_group(msg["name"], msg["policy"])
    # Save base policy in ACL manager so rules can merge on top
    if ACL_MANAGER_KEY in hass.data:
        hass.data[ACL_MANAGER_KEY].save_base_policy(group.id, msg["policy"])
    connection.send_message(
        websocket_api.result_message(msg["id"], {"group": _group_info(group)})
    )


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/auth/group/update",
        vol.Required("group_id"): str,
        vol.Optional("name"): str,
        vol.Optional("policy"): POLICY_SCHEMA,
    }
)
@websocket_api.async_response
async def websocket_group_update(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Update a custom group."""
    group = await hass.auth.async_get_group(msg["group_id"])
    if group is None:
        connection.send_message(
            websocket_api.error_message(
                msg["id"], websocket_api.ERR_NOT_FOUND, "Group not found"
            )
        )
        return

    user = connection.user
    new_policy = msg.get("policy")
    members = await _group_members(hass, group.id)
    if not can_modify_group(user, group.id, members) or (
        new_policy is not None and not can_grant(user, new_policy)
    ):
        _send_unauthorized(connection, msg["id"])
        return

    try:
        await hass.auth.async_update_group(
            group, name=msg.get("name"), policy=msg.get("policy")
        )
    except ValueError as err:
        connection.send_message(
            websocket_api.error_message(
                msg["id"], "cannot_modify_system_group", str(err)
            )
        )
        return

    # Update base policy in ACL manager if policy was changed
    if msg.get("policy") is not None and ACL_MANAGER_KEY in hass.data:
        hass.data[ACL_MANAGER_KEY].save_base_policy(group.id, msg["policy"])

    connection.send_message(
        websocket_api.result_message(msg["id"], {"group": _group_info(group)})
    )


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/auth/group/delete",
        vol.Required("group_id"): str,
    }
)
@websocket_api.async_response
async def websocket_group_delete(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Delete a custom group."""
    group = await hass.auth.async_get_group(msg["group_id"])
    if group is None:
        connection.send_message(
            websocket_api.error_message(
                msg["id"], websocket_api.ERR_NOT_FOUND, "Group not found"
            )
        )
        return

    members = await _group_members(hass, group.id)
    if not can_modify_group(connection.user, group.id, members):
        _send_unauthorized(connection, msg["id"])
        return

    try:
        await hass.auth.async_delete_group(group)
    except ValueError as err:
        connection.send_message(
            websocket_api.error_message(
                msg["id"], "cannot_delete_group", str(err)
            )
        )
        return

    connection.send_message(websocket_api.result_message(msg["id"]))


def _group_info(group: Any) -> dict[str, Any]:
    """Format a group."""
    return {
        "id": group.id,
        "name": group.name,
        "policy": group.policy,
        "system_generated": group.system_generated,
    }


def _user_info(user: User) -> dict[str, Any]:
    """Format a user."""

    ha_username = next(
        (
            cred.data.get("username")
            for cred in user.credentials
            if cred.auth_provider_type == "homeassistant"
        ),
        None,
    )

    return {
        "id": user.id,
        "username": ha_username,
        "name": user.name,
        "is_owner": user.is_owner,
        "is_active": user.is_active,
        "local_only": user.local_only,
        "system_generated": user.system_generated,
        "group_ids": [group.id for group in user.groups],
        "credentials": [{"type": c.auth_provider_type} for c in user.credentials],
    }
