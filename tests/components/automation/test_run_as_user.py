"""Automations run as the invoking user (manual) or their creator (automatic)."""

from homeassistant.components.automation import async_get_owner, async_record_owner
from homeassistant.core import Context, HomeAssistant
from homeassistant.setup import async_setup_component

from tests.common import MockUser, async_mock_service


async def test_record_owner_first_writer_wins(hass: HomeAssistant) -> None:
    """The creator is the first writer; later writers don't override."""
    await async_record_owner(hass, "auto-x", "user-1")
    await async_record_owner(hass, "auto-x", "user-2")
    assert async_get_owner(hass, "auto-x") == "user-1"
    assert async_get_owner(hass, "unknown") is None


async def test_manual_trigger_runs_as_invoking_user(
    hass: HomeAssistant, hass_owner_user: MockUser
) -> None:
    """A manual trigger runs the actions as the invoking user (invoker rights)."""
    calls = async_mock_service(hass, "test", "automation")
    assert await async_setup_component(
        hass,
        "automation",
        {
            "automation": {
                "alias": "a1",
                "id": "a1",
                "trigger": {"platform": "event", "event_type": "manual_evt"},
                "action": {"service": "test.automation"},
            }
        },
    )
    await hass.services.async_call(
        "automation",
        "trigger",
        {"entity_id": "automation.a1"},
        blocking=True,
        context=Context(user_id=hass_owner_user.id),
    )
    await hass.async_block_till_done()
    assert calls[-1].context.user_id == hass_owner_user.id


async def test_automatic_trigger_runs_as_owner(
    hass: HomeAssistant, hass_owner_user: MockUser
) -> None:
    """An automatic trigger runs the actions as the automation's creator."""
    calls = async_mock_service(hass, "test", "automation")
    assert await async_setup_component(
        hass,
        "automation",
        {
            "automation": {
                "alias": "a2",
                "id": "a2",
                "trigger": {"platform": "event", "event_type": "auto_evt"},
                "action": {"service": "test.automation"},
            }
        },
    )
    await async_record_owner(hass, "a2", hass_owner_user.id)
    hass.bus.async_fire("auto_evt")  # automatic: no user in context
    await hass.async_block_till_done()
    assert calls[-1].context.user_id == hass_owner_user.id
