"""Provide configuration end points for Automations."""

from typing import Any
import uuid

from aiohttp import web
import voluptuous as vol

from homeassistant.auth.permissions import (
    can_author_automations,
    can_set_automation_owner,
)
from homeassistant.components import websocket_api
from homeassistant.components.automation import (
    DOMAIN as AUTOMATION_DOMAIN,
    async_get_owner,
    async_record_owner,
    async_remove_owner,
    async_set_owner,
)
from homeassistant.components.automation.config import (  # pylint: disable=home-assistant-component-root-import
    async_validate_config_item,
)
from homeassistant.components.http import KEY_HASS, KEY_HASS_USER
from homeassistant.config import AUTOMATION_CONFIG_PATH
from homeassistant.const import CONF_ID, SERVICE_RELOAD
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import Unauthorized
from homeassistant.helpers import config_validation as cv, entity_registry as er

from .const import ACTION_DELETE
from .view import EditIdBasedConfigView


@callback
def async_setup(hass: HomeAssistant) -> bool:
    """Set up the Automation config API."""

    async def hook(action: str, config_key: str) -> None:
        """post_write_hook for Config View that reloads automations."""
        if action != ACTION_DELETE:
            await hass.services.async_call(
                AUTOMATION_DOMAIN, SERVICE_RELOAD, {CONF_ID: config_key}
            )
            return

        # Drop the recorded owner so it can't leak to a future automation
        # that reuses the id.
        await async_remove_owner(hass, config_key)

        ent_reg = er.async_get(hass)

        entity_id = ent_reg.async_get_entity_id(
            AUTOMATION_DOMAIN, AUTOMATION_DOMAIN, config_key
        )

        if entity_id is None:
            return

        ent_reg.async_remove(entity_id)

    hass.http.register_view(
        EditAutomationConfigView(
            AUTOMATION_DOMAIN,
            "config",
            AUTOMATION_CONFIG_PATH,
            cv.string,
            post_write_hook=hook,
            data_validator=async_validate_config_item,
        )
    )
    websocket_api.async_register_command(hass, websocket_set_owner)
    websocket_api.async_register_command(hass, websocket_get_owner)
    return True


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/automation/get_owner",
        vol.Required("automation_id"): str,
    }
)
@callback
def websocket_get_owner(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Return the run-as owner of an automation (null if unowned).

    Readable by any authenticated user: ownership is metadata the UI needs to
    decide whether to offer transfer or a personal copy. Mutating it still goes
    through set_owner and its authority checks.
    """
    connection.send_message(
        websocket_api.result_message(
            msg["id"],
            {"owner_id": async_get_owner(hass, msg["automation_id"])},
        )
    )


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/automation/set_owner",
        vol.Required("automation_id"): str,
        vol.Required("user_id"): str,
    }
)
@websocket_api.async_response
async def websocket_set_owner(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Set the run-as owner of an automation (transfer / adoption)."""
    new_owner = await hass.auth.async_get_user(msg["user_id"])
    if new_owner is None:
        connection.send_message(
            websocket_api.error_message(
                msg["id"], websocket_api.ERR_NOT_FOUND, "User not found"
            )
        )
        return

    current_owner_id = async_get_owner(hass, msg["automation_id"])
    current_owner = (
        await hass.auth.async_get_user(current_owner_id) if current_owner_id else None
    )

    if not can_set_automation_owner(connection.user, current_owner, new_owner):
        connection.send_message(
            websocket_api.error_message(
                msg["id"],
                websocket_api.ERR_UNAUTHORIZED,
                "Not authorized to set this automation's owner",
            )
        )
        return

    await async_set_owner(hass, msg["automation_id"], new_owner.id)
    connection.send_message(websocket_api.result_message(msg["id"]))


class EditAutomationConfigView(EditIdBasedConfigView):
    """Edit automation config."""

    def _authorize(self, request: web.Request) -> None:
        """Allow admins and any user permitted to author automations."""
        user = request[KEY_HASS_USER]
        if user is None or not can_author_automations(user):
            raise Unauthorized

    async def post(self, request: web.Request, config_key: str) -> web.Response:
        """Persist config and record the creating user as the owner."""
        # super().post() runs _authorize() (admins or automation authors).
        response = await super().post(request, config_key)
        if response.status < 400 and (user := request[KEY_HASS_USER]) is not None:
            # First writer wins, so this records the creator. Automatic
            # triggers then run with the creator's permissions.
            await async_record_owner(request.app[KEY_HASS], config_key, user.id)
        return response

    def _write_value(
        self,
        hass: HomeAssistant,
        data: list[dict[str, Any]],
        config_key: str,
        new_value: dict[str, Any],
    ) -> None:
        """Set value."""
        updated_value = {CONF_ID: config_key}

        # Iterate through some keys that we want to have ordered in the output
        for key in (
            "alias",
            "description",
            "triggers",
            "trigger",
            "conditions",
            "condition",
            "actions",
            "action",
        ):
            if key in new_value:
                updated_value[key] = new_value[key]

        # We cover all current fields above, but just in case we start
        # supporting more fields in the future.
        updated_value.update(new_value)

        updated = False
        for index, cur_value in enumerate(data):
            # When people copy paste their automations to the config file,
            # they sometimes forget to add IDs. Fix it here.
            if CONF_ID not in cur_value:
                cur_value[CONF_ID] = uuid.uuid4().hex

            elif cur_value[CONF_ID] == config_key:
                data[index] = updated_value
                updated = True

        if not updated:
            data.append(updated_value)
