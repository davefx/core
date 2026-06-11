"""A script runs its actions as the invoking user (so the ACL applies)."""

from homeassistant.core import Context, HomeAssistant
from homeassistant.setup import async_setup_component

from tests.common import async_mock_service


async def test_script_runs_actions_as_invoker(
    hass: HomeAssistant, hass_owner_user
) -> None:
    """Service calls a script makes carry the invoking user's context."""
    calls = async_mock_service(hass, "test", "act")
    assert await async_setup_component(
        hass,
        "script",
        {"script": {"s1": {"sequence": [{"service": "test.act"}]}}},
    )
    await hass.services.async_call(
        "script", "s1", blocking=True, context=Context(user_id=hass_owner_user.id)
    )
    await hass.async_block_till_done()
    assert calls[-1].context.user_id == hass_owner_user.id
