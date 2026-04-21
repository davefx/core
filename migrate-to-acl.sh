#!/bin/bash
# =============================================================================
# Migrate Home Assistant OS to ACL-patched fork
# =============================================================================
#
# This script switches a standard HA OS installation to use the ACL-patched
# HA Core images from ghcr.io/davefx. Run it via the Terminal & SSH add-on
# or SSH access to the HA OS host.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/davefx/core/acl-patches/migrate-to-acl.sh | bash
#
# To revert to official HA:
#   curl -sSL https://raw.githubusercontent.com/davefx/core/acl-patches/migrate-to-acl.sh | bash -s -- --revert
#
# =============================================================================

set -euo pipefail

FORK_OWNER="davefx"
VERSION_URL="https://davefx.github.io/core/version.json"
REVERT=false

if [[ "${1:-}" == "--revert" ]]; then
  REVERT=true
fi

# Detect machine type
MACHINE=$(ha info --raw-json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['machine'])" 2>/dev/null || echo "")

if [[ -z "$MACHINE" ]]; then
  echo "ERROR: Could not detect machine type. Are you running this on HA OS?"
  echo "Make sure you're running this from the Terminal & SSH add-on or host SSH."
  exit 1
fi

echo "Detected machine: $MACHINE"

if [[ "$REVERT" == "true" ]]; then
  echo ""
  echo "=== Reverting to official Home Assistant ==="
  echo ""

  # Get current HA version
  CURRENT_VERSION=$(ha core info --raw-json | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['version'])")
  OFFICIAL_IMAGE="ghcr.io/home-assistant/${MACHINE}-homeassistant"

  echo "Switching back to official image: $OFFICIAL_IMAGE"
  ha core options --image "$OFFICIAL_IMAGE"

  echo "Reinstalling official version $CURRENT_VERSION..."
  ha core rebuild

  echo ""
  echo "=== Revert complete ==="
  echo "You are now running official Home Assistant."
  echo "Auto-updates will work normally."
  exit 0
fi

# === Migration to ACL fork ===

echo ""
echo "=== Migrating to ACL-patched Home Assistant ==="
echo ""

# Fetch available version from our manifest
echo "Checking available version..."
AVAILABLE_VERSION=$(python3 -c "
import urllib.request, json
data = json.loads(urllib.request.urlopen('$VERSION_URL').read())
machine_versions = data.get('homeassistant', {})
print(machine_versions.get('$MACHINE', ''))
")

if [[ -z "$AVAILABLE_VERSION" ]]; then
  echo "ERROR: No ACL build available for machine '$MACHINE'."
  echo "Available machines:"
  python3 -c "
import urllib.request, json
data = json.loads(urllib.request.urlopen('$VERSION_URL').read())
for m in data.get('homeassistant', {}):
    print(f'  - {m}')
"
  exit 1
fi

CURRENT_VERSION=$(ha core info --raw-json | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['version'])")
FORK_IMAGE="ghcr.io/${FORK_OWNER}/${MACHINE}-homeassistant"

echo "Current version:   $CURRENT_VERSION"
echo "ACL fork version:  $AVAILABLE_VERSION"
echo "Fork image:        $FORK_IMAGE"
echo ""

# Check version compatibility
if [[ "$CURRENT_VERSION" != "$AVAILABLE_VERSION" ]]; then
  echo "WARNING: Your HA version ($CURRENT_VERSION) differs from the ACL fork ($AVAILABLE_VERSION)."
  echo "The migration will install version $AVAILABLE_VERSION."
  echo ""
  read -p "Continue? [y/N] " -n 1 -r
  echo ""
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
  fi
fi

# Create backup first
echo "Creating backup before migration..."
ha backups new --name "pre-acl-migration-$(date +%Y%m%d)" || echo "WARNING: Backup failed, continuing anyway..."

# Switch to custom image
echo ""
echo "Switching to ACL fork image..."
ha core options --image "$FORK_IMAGE"

# Update to the ACL fork version
echo "Pulling ACL-patched version $AVAILABLE_VERSION..."
ha core update --version "$AVAILABLE_VERSION" || {
  echo ""
  echo "ERROR: Update failed. Reverting to official image..."
  ha core options --image "ghcr.io/home-assistant/${MACHINE}-homeassistant"
  exit 1
}

echo ""
echo "=== Migration complete ==="
echo ""
echo "You are now running Home Assistant $AVAILABLE_VERSION with ACL patches."
echo ""
echo "IMPORTANT: Auto-updates are disabled for HA Core."
echo "To update in the future, re-run this script when a new ACL build is available."
echo ""
echo "To revert to official HA at any time:"
echo "  curl -sSL https://raw.githubusercontent.com/davefx/core/acl-patches/migrate-to-acl.sh | bash -s -- --revert"
echo ""
echo "New features available:"
echo "  - Custom roles with deny rules (WebSocket: config/auth/group/create)"
echo "  - Label-based entity permissions"
echo "  - Per-service permissions"
echo "  - Per-automation permissions (read/edit/trigger)"
echo "  - ACL rule management (WebSocket: config/acl/rules/*)"
echo "  - Audit logging (WebSocket: config/acl/audit/*)"
echo "  - Time-based conditional access"
