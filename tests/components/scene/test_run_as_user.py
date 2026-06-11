"""A scene reproduces its states as the invoking user (so the ACL applies)."""

from homeassistant.core import Context, HomeAssistant
from homeassistant.setup import async_setup_component


async def test_scene_reproduces_actions_as_invoker(
    hass: HomeAssistant, hass_owner_user
) -> None:
    """Actions a scene reproduces carry the invoking user's context."""
    assert await async_setup_component(
        hass, "input_boolean", {"input_boolean": {"x": None}}
    )
    await hass.async_block_till_done()
    hass.states.async_set("input_boolean.x", "off")
    assert await async_setup_component(
        hass,
        "scene",
        {"scene": [{"name": "sc", "entities": {"input_boolean.x": "on"}}]},
    )
    await hass.async_block_till_done()
    await hass.services.async_call(
        "scene",
        "turn_on",
        {"entity_id": "scene.sc"},
        blocking=True,
        context=Context(user_id=hass_owner_user.id),
    )
    await hass.async_block_till_done()
    assert hass.states.get("input_boolean.x").context.user_id == hass_owner_user.id
