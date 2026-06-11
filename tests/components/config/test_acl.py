"""Test the ACL rules config API and its delegated authorization."""

import pytest

from homeassistant.auth.models import Group, User
from homeassistant.components.config import acl as acl_config
from homeassistant.core import HomeAssistant

from tests.common import CLIENT_ID, MockUser
from tests.typing import ClientSessionGenerator, WebSocketGenerator


@pytest.fixture(autouse=True)
async def setup_acl(
    hass: HomeAssistant, aiohttp_client: ClientSessionGenerator
) -> None:
    """Set up the ACL config endpoints."""
    acl_config.async_setup(hass)


async def _token(hass: HomeAssistant, user: User) -> str:
    """Mint an access token for a user."""
    refresh_token = await hass.auth.async_create_refresh_token(user, CLIENT_ID)
    return hass.auth.async_create_access_token(refresh_token)


async def _make_target_role(hass: HomeAssistant) -> tuple[Group, User]:
    """Create a role group granting light.kitchen plus one subordinate member."""
    target = await hass.auth.async_create_group(
        "Target",
        {"entities": {"entity_ids": {"light.kitchen": {"control": True}}}},
    )
    subordinate = MockUser(name="Worker", groups=[target]).add_to_hass(hass)
    subordinate.mock_policy(
        {"entities": {"entity_ids": {"light.kitchen": {"control": True}}}}
    )
    return target, subordinate


async def _make_manager(hass: HomeAssistant, target: Group) -> User:
    """A non-admin who can manage `target` and outranks its members."""
    mgr_group = await hass.auth.async_create_group(
        "Managers",
        {
            "admin": {"groups": {"group_ids": {target.id: {"manage": True}}}},
            "entities": {
                "entity_ids": {
                    "light.kitchen": {"control": True},
                    "light.living": {"control": True},
                }
            },
        },
    )
    manager = MockUser(name="Manager", groups=[mgr_group]).add_to_hass(hass)
    assert not manager.is_admin
    return manager


async def test_rules_create_owner(
    hass: HomeAssistant, hass_ws_client: WebSocketGenerator, hass_owner_user: MockUser
) -> None:
    """The owner can always create a rule."""
    target, _sub = await _make_target_role(hass)
    client = await hass_ws_client(hass, await _token(hass, hass_owner_user))

    await client.send_json(
        {
            "id": 5,
            "type": "config/acl/rules/create",
            "role_id": target.id,
            "category": "entities",
            "target_type": "entity_ids",
            "target_id": "lock.door",
            "permission": "control",
            "effect": "deny",
        }
    )
    assert (await client.receive_json())["success"]


async def test_rules_create_delegated_manager(
    hass: HomeAssistant, hass_ws_client: WebSocketGenerator
) -> None:
    """A delegated manager can write a rule within their authority."""
    target, _sub = await _make_target_role(hass)
    manager = await _make_manager(hass, target)
    client = await hass_ws_client(hass, await _token(hass, manager))

    await client.send_json(
        {
            "id": 5,
            "type": "config/acl/rules/create",
            "role_id": target.id,
            "category": "entities",
            "target_type": "entity_ids",
            "target_id": "light.kitchen",
            "permission": "control",
            "effect": "deny",
        }
    )
    assert (await client.receive_json())["success"]


async def test_rules_create_beyond_authority(
    hass: HomeAssistant, hass_ws_client: WebSocketGenerator
) -> None:
    """A manager can't write a rule over a scope they don't hold."""
    target, _sub = await _make_target_role(hass)
    manager = await _make_manager(hass, target)
    client = await hass_ws_client(hass, await _token(hass, manager))

    await client.send_json(
        {
            "id": 5,
            "type": "config/acl/rules/create",
            "role_id": target.id,
            "category": "entities",
            "target_type": "entity_ids",
            "target_id": "lock.door",
            "permission": "control",
            "effect": "allow",
        }
    )
    result = await client.receive_json()
    assert not result["success"]
    assert result["error"]["code"] == "unauthorized"


async def test_rules_create_blocks_self_role(
    hass: HomeAssistant, hass_ws_client: WebSocketGenerator
) -> None:
    """A manager can't edit the rules of a role they belong to."""
    target, _sub = await _make_target_role(hass)
    manager = await _make_manager(hass, target)
    # Make the manager a member of the very role they manage.
    manager.groups.append(target)
    client = await hass_ws_client(hass, await _token(hass, manager))

    await client.send_json(
        {
            "id": 5,
            "type": "config/acl/rules/create",
            "role_id": target.id,
            "category": "entities",
            "target_type": "entity_ids",
            "target_id": "light.kitchen",
            "permission": "control",
            "effect": "deny",
        }
    )
    result = await client.receive_json()
    assert not result["success"]
    assert result["error"]["code"] == "unauthorized"


async def test_rules_update_pivot_blocked(
    hass: HomeAssistant, hass_ws_client: WebSocketGenerator, hass_owner_user: MockUser
) -> None:
    """A manager can't pivot an existing rule onto a scope beyond their reach."""
    target, _sub = await _make_target_role(hass)
    manager = await _make_manager(hass, target)

    # Owner seeds a rule the manager does have authority over.
    owner_client = await hass_ws_client(hass, await _token(hass, hass_owner_user))
    await owner_client.send_json(
        {
            "id": 1,
            "type": "config/acl/rules/create",
            "role_id": target.id,
            "category": "entities",
            "target_type": "entity_ids",
            "target_id": "light.kitchen",
            "permission": "control",
            "effect": "deny",
        }
    )
    created = await owner_client.receive_json()
    assert created["success"]
    rule_id = created["result"]["rule"]["id"]

    mgr_client = await hass_ws_client(hass, await _token(hass, manager))
    await mgr_client.send_json(
        {
            "id": 2,
            "type": "config/acl/rules/update",
            "rule_id": rule_id,
            "target_id": "lock.door",
            "effect": "allow",
        }
    )
    result = await mgr_client.receive_json()
    assert not result["success"]
    assert result["error"]["code"] == "unauthorized"


async def test_rules_delete_delegated_manager(
    hass: HomeAssistant, hass_ws_client: WebSocketGenerator, hass_owner_user: MockUser
) -> None:
    """A manager can delete a rule within their authority."""
    target, _sub = await _make_target_role(hass)
    manager = await _make_manager(hass, target)

    owner_client = await hass_ws_client(hass, await _token(hass, hass_owner_user))
    await owner_client.send_json(
        {
            "id": 1,
            "type": "config/acl/rules/create",
            "role_id": target.id,
            "category": "entities",
            "target_type": "entity_ids",
            "target_id": "light.kitchen",
            "permission": "control",
            "effect": "deny",
        }
    )
    created = await owner_client.receive_json()
    rule_id = created["result"]["rule"]["id"]

    mgr_client = await hass_ws_client(hass, await _token(hass, manager))
    await mgr_client.send_json(
        {
            "id": 2,
            "type": "config/acl/rules/delete",
            "rule_id": rule_id,
        }
    )
    assert (await mgr_client.receive_json())["success"]
