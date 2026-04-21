"""Constants for ACL fork update manager."""

from datetime import timedelta

DOMAIN = "acl_fork_manager"

VERSION_URL = "https://davefx.github.io/core/version.json"
FORK_OWNER = "davefx"
FORK_IMAGE_TEMPLATE = "ghcr.io/{owner}/{machine}-homeassistant"

# Check for updates every 6 hours
UPDATE_CHECK_INTERVAL = timedelta(hours=6)

# Re-apply image override 30 seconds after startup
STARTUP_DELAY = 30
