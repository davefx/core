"""Test Automation config panel."""

from http import HTTPStatus
import json
from typing import Any
from unittest.mock import patch

import pytest

from homeassistant.components import config
from homeassistant.components.config import automation
from homeassistant.const import STATE_ON
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.setup import async_setup_component
from homeassistant.util import yaml as yaml_util

from tests.common import MockUser
from tests.typing import ClientSessionGenerator, WebSocketGenerator


@pytest.fixture
async def setup_automation(
    hass: HomeAssistant,
    automation_config: dict[str, Any],
) -> None:
    """Set up automation integration."""
    assert await async_setup_component(
        hass, "automation", {"automation": automation_config}
    )


@pytest.mark.parametrize("automation_config", [{}])
@pytest.mark.usefixtures("setup_automation")
async def test_get_automation_config(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_config_store: dict[str, Any],
) -> None:
    """Test getting automation config."""
    with patch.object(config, "SECTIONS", [automation]):
        await async_setup_component(hass, "config", {})

    client = await hass_client()

    hass_config_store["automations.yaml"] = [{"id": "sun"}, {"id": "moon"}]

    resp = await client.get("/api/config/automation/config/moon")

    assert resp.status == HTTPStatus.OK
    result = await resp.json()

    assert result == {"id": "moon"}


@pytest.mark.parametrize("automation_config", [{}])
@pytest.mark.usefixtures("setup_automation")
async def test_update_automation_config(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_config_store: dict[str, Any],
) -> None:
    """Test updating automation config."""
    with patch.object(config, "SECTIONS", [automation]):
        await async_setup_component(hass, "config", {})

    assert sorted(hass.states.async_entity_ids("automation")) == []

    client = await hass_client()

    orig_data = [{"id": "sun"}, {"id": "moon"}]
    hass_config_store["automations.yaml"] = orig_data

    resp = await client.post(
        "/api/config/automation/config/moon",
        data=json.dumps({"triggers": [], "actions": [], "conditions": []}),
    )
    await hass.async_block_till_done()
    assert sorted(hass.states.async_entity_ids("automation")) == [
        "automation.automation_1",
    ]
    assert hass.states.get("automation.automation_1").state == STATE_ON

    assert resp.status == HTTPStatus.OK
    result = await resp.json()
    assert result == {"result": "ok"}

    new_data = hass_config_store["automations.yaml"]
    assert list(new_data[1]) == ["id", "triggers", "conditions", "actions"]
    assert new_data[1] == {
        "id": "moon",
        "triggers": [],
        "conditions": [],
        "actions": [],
    }


@pytest.mark.parametrize("automation_config", [{}])
@pytest.mark.parametrize(
    ("updated_config", "validation_error"),
    [
        (
            {"action": []},
            "required key not provided @ data['triggers']",
        ),
        (
            {
                "trigger": {"trigger": "automation"},
                "action": [],
            },
            "Integration 'automation' does not provide trigger support",
        ),
        (
            {
                "trigger": {"trigger": "event", "event_type": "test_event"},
                "condition": {
                    "condition": "state",
                    # The UUID will fail being resolved to en entity_id
                    "entity_id": "abcdabcdabcdabcdabcdabcdabcdabcd",
                    "state": "blah",
                },
                "action": [],
            },
            "Unknown entity registry entry abcdabcdabcdabcdabcdabcdabcdabcd",
        ),
        (
            {
                "trigger": {"trigger": "event", "event_type": "test_event"},
                "action": {
                    "condition": "state",
                    # The UUID will fail being resolved to en entity_id
                    "entity_id": "abcdabcdabcdabcdabcdabcdabcdabcd",
                    "state": "blah",
                },
            },
            "Unknown entity registry entry abcdabcdabcdabcdabcdabcdabcdabcd",
        ),
        (
            {
                "use_blueprint": {"path": "test_event_service.yaml", "input": {}},
            },
            "Missing input a_number, service_to_call, trigger_event",
        ),
    ],
)
@pytest.mark.usefixtures("setup_automation")
async def test_update_automation_config_with_error(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_config_store: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
    updated_config: Any,
    validation_error: str,
) -> None:
    """Test updating automation config with errors."""
    with patch.object(config, "SECTIONS", [automation]):
        await async_setup_component(hass, "config", {})

    assert sorted(hass.states.async_entity_ids("automation")) == []

    client = await hass_client()

    orig_data = [{"id": "sun"}, {"id": "moon"}]
    hass_config_store["automations.yaml"] = orig_data

    resp = await client.post(
        "/api/config/automation/config/moon",
        data=json.dumps(updated_config),
    )
    await hass.async_block_till_done()
    assert sorted(hass.states.async_entity_ids("automation")) == []

    assert resp.status != HTTPStatus.OK
    result = await resp.json()
    assert result == {"message": f"Message malformed: {validation_error}"}
    # Assert the validation error is not logged
    assert validation_error not in caplog.text


@pytest.mark.parametrize("automation_config", [{}])
@pytest.mark.parametrize(
    ("updated_config", "validation_error"),
    [
        (
            {
                "use_blueprint": {
                    "path": "test_event_service.yaml",
                    "input": {
                        "trigger_event": "test_event",
                        "service_to_call": "test.automation",
                        "a_number": 5,
                    },
                },
            },
            "No substitution found for input blah",
        ),
    ],
)
@pytest.mark.usefixtures("setup_automation")
async def test_update_automation_config_with_blueprint_substitution_error(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_config_store: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
    updated_config: Any,
    validation_error: str,
) -> None:
    """Test updating automation config with errors."""
    with patch.object(config, "SECTIONS", [automation]):
        await async_setup_component(hass, "config", {})

    assert sorted(hass.states.async_entity_ids("automation")) == []

    client = await hass_client()

    orig_data = [{"id": "sun"}, {"id": "moon"}]
    hass_config_store["automations.yaml"] = orig_data

    with patch(
        "homeassistant.components.blueprint.models.BlueprintInputs.async_substitute",
        side_effect=yaml_util.UndefinedSubstitution("blah"),
    ):
        resp = await client.post(
            "/api/config/automation/config/moon",
            data=json.dumps(updated_config),
        )
        await hass.async_block_till_done()
    assert sorted(hass.states.async_entity_ids("automation")) == []

    assert resp.status != HTTPStatus.OK
    result = await resp.json()
    assert result == {"message": f"Message malformed: {validation_error}"}
    # Assert the validation error is not logged
    assert validation_error not in caplog.text


@pytest.mark.parametrize("automation_config", [{}])
@pytest.mark.usefixtures("setup_automation")
async def test_update_remove_key_automation_config(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_config_store: dict[str, Any],
) -> None:
    """Test updating automation config while removing a key."""
    with patch.object(config, "SECTIONS", [automation]):
        await async_setup_component(hass, "config", {})

    assert sorted(hass.states.async_entity_ids("automation")) == []

    client = await hass_client()

    orig_data = [{"id": "sun", "key": "value"}, {"id": "moon", "key": "value"}]
    hass_config_store["automations.yaml"] = orig_data

    resp = await client.post(
        "/api/config/automation/config/moon",
        data=json.dumps({"triggers": [], "actions": [], "conditions": []}),
    )
    await hass.async_block_till_done()
    assert sorted(hass.states.async_entity_ids("automation")) == [
        "automation.automation_1",
    ]
    assert hass.states.get("automation.automation_1").state == STATE_ON

    assert resp.status == HTTPStatus.OK
    result = await resp.json()
    assert result == {"result": "ok"}

    new_data = hass_config_store["automations.yaml"]
    assert list(new_data[1]) == ["id", "triggers", "conditions", "actions"]
    assert new_data[1] == {
        "id": "moon",
        "triggers": [],
        "conditions": [],
        "actions": [],
    }


@pytest.mark.parametrize("automation_config", [{}])
@pytest.mark.usefixtures("setup_automation")
async def test_bad_formatted_automations(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_config_store: dict[str, Any],
) -> None:
    """Test that we handle automations without ID."""
    with patch.object(config, "SECTIONS", [automation]):
        await async_setup_component(hass, "config", {})

    assert sorted(hass.states.async_entity_ids("automation")) == []

    client = await hass_client()

    orig_data = [
        {
            # No ID
            "action": {"event": "hello"}
        },
        {"id": "moon"},
    ]
    hass_config_store["automations.yaml"] = orig_data

    resp = await client.post(
        "/api/config/automation/config/moon",
        data=json.dumps({"triggers": [], "actions": [], "conditions": []}),
    )
    await hass.async_block_till_done()
    assert sorted(hass.states.async_entity_ids("automation")) == [
        "automation.automation_1",
    ]
    assert hass.states.get("automation.automation_1").state == STATE_ON

    assert resp.status == HTTPStatus.OK
    result = await resp.json()
    assert result == {"result": "ok"}

    # Verify ID added
    new_data = hass_config_store["automations.yaml"]
    assert "id" in new_data[0]
    assert new_data[1] == {
        "id": "moon",
        "triggers": [],
        "conditions": [],
        "actions": [],
    }


@pytest.mark.parametrize(
    "automation_config",
    [
        [
            {
                "id": "sun",
                "trigger": {"trigger": "event", "event_type": "test_event"},
                "action": {"service": "test.automation"},
            },
            {
                "id": "moon",
                "trigger": {"trigger": "event", "event_type": "test_event"},
                "action": {"service": "test.automation"},
            },
        ],
    ],
)
@pytest.mark.usefixtures("setup_automation")
async def test_delete_automation(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    entity_registry: er.EntityRegistry,
    hass_config_store: dict[str, Any],
) -> None:
    """Test deleting an automation."""

    assert len(entity_registry.entities) == 2

    with patch.object(config, "SECTIONS", [automation]):
        assert await async_setup_component(hass, "config", {})

    assert sorted(hass.states.async_entity_ids("automation")) == [
        "automation.automation_0",
        "automation.automation_1",
    ]

    client = await hass_client()

    orig_data = [{"id": "sun"}, {"id": "moon"}]
    hass_config_store["automations.yaml"] = orig_data

    resp = await client.delete("/api/config/automation/config/sun")
    await hass.async_block_till_done()

    assert sorted(hass.states.async_entity_ids("automation")) == [
        "automation.automation_1",
    ]

    assert resp.status == HTTPStatus.OK
    result = await resp.json()
    assert result == {"result": "ok"}

    assert hass_config_store["automations.yaml"] == [{"id": "moon"}]

    assert len(entity_registry.entities) == 1


@pytest.mark.parametrize("automation_config", [{}])
@pytest.mark.usefixtures("setup_automation")
async def test_api_calls_require_admin(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_read_only_access_token: str,
    hass_config_store: dict[str, Any],
) -> None:
    """Test cloud APIs endpoints do not work as a normal user."""
    with patch.object(config, "SECTIONS", [automation]):
        await async_setup_component(hass, "config", {})

    hass_config_store["automations.yaml"] = [{"id": "sun"}, {"id": "moon"}]

    client = await hass_client(hass_read_only_access_token)

    # Get
    resp = await client.get("/api/config/automation/config/moon")
    assert resp.status == HTTPStatus.UNAUTHORIZED

    # Update
    resp = await client.post(
        "/api/config/automation/config/moon",
        data=json.dumps({"trigger": [], "action": [], "condition": []}),
    )
    assert resp.status == HTTPStatus.UNAUTHORIZED

    # Delete
    resp = await client.delete("/api/config/automation/config/sun")
    assert resp.status == HTTPStatus.UNAUTHORIZED


@pytest.mark.parametrize("automation_config", [{}])
@pytest.mark.usefixtures("setup_automation")
async def test_set_owner_admin_adopts(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
) -> None:
    """An admin can set the run-as owner of an unowned automation."""
    with patch.object(config, "SECTIONS", [automation]):
        await async_setup_component(hass, "config", {})

    target = await hass.auth.async_create_user("Target")
    client = await hass_ws_client(hass)

    await client.send_json(
        {
            "id": 6,
            "type": "config/automation/set_owner",
            "automation_id": "a1",
            "user_id": target.id,
        }
    )
    result = await client.receive_json()
    assert result["success"], result
    assert automation.async_get_owner(hass, "a1") == target.id


@pytest.mark.parametrize("automation_config", [{}])
@pytest.mark.usefixtures("setup_automation")
async def test_get_owner(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
) -> None:
    """get_owner returns null for an unowned automation, then the set owner."""
    with patch.object(config, "SECTIONS", [automation]):
        await async_setup_component(hass, "config", {})

    target = await hass.auth.async_create_user("Target")
    client = await hass_ws_client(hass)

    await client.send_json(
        {"id": 5, "type": "config/automation/get_owner", "automation_id": "a1"}
    )
    result = await client.receive_json()
    assert result["success"], result
    assert result["result"] == {"owner_id": None}

    await automation.async_set_owner(hass, "a1", target.id)

    await client.send_json(
        {"id": 6, "type": "config/automation/get_owner", "automation_id": "a1"}
    )
    result = await client.receive_json()
    assert result["result"] == {"owner_id": target.id}


@pytest.mark.parametrize("automation_config", [{}])
@pytest.mark.usefixtures("setup_automation")
async def test_set_owner_unknown_user(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
) -> None:
    """Setting the owner to a nonexistent user is rejected."""
    with patch.object(config, "SECTIONS", [automation]):
        await async_setup_component(hass, "config", {})

    client = await hass_ws_client(hass)
    await client.send_json(
        {
            "id": 6,
            "type": "config/automation/set_owner",
            "automation_id": "a1",
            "user_id": "does-not-exist",
        }
    )
    result = await client.receive_json()
    assert not result["success"]
    assert result["error"]["code"] == "not_found"


@pytest.mark.parametrize("automation_config", [{}])
@pytest.mark.usefixtures("setup_automation")
async def test_set_owner_requires_authority(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    hass_read_only_access_token: str,
) -> None:
    """A user without authoring authority can't reassign an automation."""
    with patch.object(config, "SECTIONS", [automation]):
        await async_setup_component(hass, "config", {})

    target = MockUser(name="Target").add_to_hass(hass)
    client = await hass_ws_client(hass, hass_read_only_access_token)

    await client.send_json(
        {
            "id": 6,
            "type": "config/automation/set_owner",
            "automation_id": "a1",
            "user_id": target.id,
        }
    )
    result = await client.receive_json()
    assert not result["success"]
    assert result["error"]["code"] == "unauthorized"
    assert automation.async_get_owner(hass, "a1") is None
