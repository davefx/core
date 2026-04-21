"""ACL fork update manager.

Automatically keeps the Home Assistant Core image pointed at the
ACL-patched fork. Runs as a background service that:

1. On startup, ensures the Supervisor's Core image is set to the fork.
2. Periodically checks for new ACL fork releases.
3. When a new version is available, sets the fork image and triggers
   an update via the Supervisor API.
4. Registers the ACL management panel in the sidebar.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from datetime import datetime

import aiohttp

from homeassistant.components.panel_custom import async_register_panel
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.typing import ConfigType

from .const import (
    DOMAIN,
    FORK_IMAGE_TEMPLATE,
    FORK_OWNER,
    STARTUP_DELAY,
    UPDATE_CHECK_INTERVAL,
    VERSION_URL,
)

_LOGGER = logging.getLogger(__name__)

PANEL_URL = "/acl_fork_manager/acl-panel.js"
PANEL_PATH = Path(__file__).parent / "frontend" / "acl-panel.js"

CONFIG_SCHEMA = cv.empty_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the ACL fork update manager."""
    # Register the ACL management panel (works in all environments)
    hass.http.register_static_path(PANEL_URL, str(PANEL_PATH), cache_headers=False)
    await async_register_panel(
        hass,
        webcomponent_name="acl-panel",
        frontend_url_path="acl",
        sidebar_title="Access control",
        sidebar_icon="mdi:shield-lock",
        module_url=PANEL_URL,
        require_admin=True,
    )

    # Only run fork updater under Supervisor (HA OS / HA Supervised)
    if "SUPERVISOR" not in os.environ:
        _LOGGER.debug("Not running under Supervisor, skipping fork updater")
        return True

    supervisor_token = os.environ.get("SUPERVISOR_TOKEN", "")
    supervisor_host = os.environ["SUPERVISOR"]
    base_url = f"http://{supervisor_host}"

    manager = ForkUpdateManager(hass, base_url, supervisor_token)
    hass.data[DOMAIN] = manager

    # Ensure fork image is set shortly after startup
    async_call_later(hass, STARTUP_DELAY, manager.async_ensure_fork_image)

    return True


class ForkUpdateManager:
    """Manage Core image updates from the ACL fork."""

    def __init__(
        self,
        hass: HomeAssistant,
        base_url: str,
        supervisor_token: str,
    ) -> None:
        """Initialize the fork update manager."""
        self.hass = hass
        self._base_url = base_url
        self._token = supervisor_token
        self._headers = {
            "Authorization": f"Bearer {supervisor_token}",
            "Content-Type": "application/json",
        }

    async def _supervisor_get(self, path: str) -> dict:
        """GET request to the Supervisor API."""
        session = async_get_clientsession(self.hass)
        async with session.get(
            f"{self._base_url}{path}",
            headers=self._headers,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as resp:
            return await resp.json()

    async def _supervisor_post(
        self, path: str, payload: dict | None = None
    ) -> dict:
        """POST request to the Supervisor API."""
        session = async_get_clientsession(self.hass)
        async with session.post(
            f"{self._base_url}{path}",
            headers=self._headers,
            json=payload or {},
            timeout=aiohttp.ClientTimeout(total=60),
        ) as resp:
            return await resp.json()

    async def _get_machine(self) -> str | None:
        """Get the machine type from the Supervisor."""
        try:
            result = await self._supervisor_get("/info")
            return result.get("data", {}).get("machine")
        except Exception:
            _LOGGER.exception("Failed to get machine info from Supervisor")
            return None

    async def _get_core_info(self) -> dict:
        """Get current Core container info."""
        try:
            result = await self._supervisor_get("/homeassistant/info")
            return result.get("data", {})
        except Exception:
            _LOGGER.exception("Failed to get Core info from Supervisor")
            return {}

    async def _set_core_image(self, image: str) -> bool:
        """Set the Core container image via Supervisor API."""
        try:
            result = await self._supervisor_post(
                "/homeassistant/options", {"image": image}
            )
            return result.get("result") == "ok"
        except Exception:
            _LOGGER.exception("Failed to set Core image to %s", image)
            return False

    async def _fetch_fork_version(self, machine: str) -> str | None:
        """Fetch the latest available version from the fork manifest."""
        try:
            session = async_get_clientsession(self.hass)
            async with session.get(
                VERSION_URL,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                data = await resp.json()
                return data.get("homeassistant", {}).get(machine)
        except Exception:
            _LOGGER.exception("Failed to fetch fork version manifest")
            return None

    @callback
    def async_ensure_fork_image(self, _now: datetime | None = None) -> None:
        """Ensure the Core image points to the fork (callback entry point)."""
        self.hass.async_create_task(
            self._async_ensure_fork_image(), eager_start=True
        )

    async def _async_ensure_fork_image(self) -> None:
        """Ensure the Core image points to the fork and check for updates."""
        machine = await self._get_machine()
        if not machine:
            _LOGGER.warning("Could not detect machine type, retrying later")
            self._schedule_next_check()
            return

        fork_image = FORK_IMAGE_TEMPLATE.format(
            owner=FORK_OWNER, machine=machine
        )
        core_info = await self._get_core_info()
        current_image = core_info.get("image", "")
        current_version = core_info.get("version", "")

        # Ensure the image is set to our fork
        if current_image != fork_image:
            _LOGGER.info(
                "Core image is '%s', switching to fork image '%s'",
                current_image,
                fork_image,
            )
            if not await self._set_core_image(fork_image):
                _LOGGER.error("Failed to set fork image, retrying later")
                self._schedule_next_check()
                return

        # Check if a newer version is available
        fork_version = await self._fetch_fork_version(machine)
        if fork_version and fork_version != current_version:
            _LOGGER.info(
                "New ACL fork version available: %s (current: %s)",
                fork_version,
                current_version,
            )
            # Ensure image is set before update
            await self._set_core_image(fork_image)
            # Trigger the update
            try:
                await self._supervisor_post(
                    "/homeassistant/update", {"version": fork_version}
                )
                _LOGGER.info(
                    "Update to %s triggered successfully", fork_version
                )
            except Exception:
                _LOGGER.exception(
                    "Failed to trigger update to %s", fork_version
                )
        else:
            _LOGGER.debug(
                "ACL fork is up to date (version %s)", current_version
            )

        self._schedule_next_check()

    def _schedule_next_check(self) -> None:
        """Schedule the next update check."""
        async_call_later(
            self.hass,
            UPDATE_CHECK_INTERVAL.total_seconds(),
            self.async_ensure_fork_image,
        )
