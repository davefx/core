"""Tests for ACL audit logging."""

from unittest.mock import MagicMock, patch

from homeassistant.auth.acl.audit import (
    AuditAction,
    AuditEntry,
    AuditLevel,
    AuditLogger,
)


def test_audit_entry_serialization() -> None:
    """Test AuditEntry to_dict and from_dict."""
    entry = AuditEntry(
        action=AuditAction.PERMISSION_DENIED,
        user_id="test-user",
        category="entities",
        target="light.kitchen",
        permission="control",
        result="denied",
    )
    data = entry.to_dict()
    assert data["action"] == "permission_denied"
    assert data["user_id"] == "test-user"
    assert data["target"] == "light.kitchen"

    restored = AuditEntry.from_dict(data)
    assert restored.id == entry.id
    assert restored.action == entry.action
    assert restored.user_id == entry.user_id


def test_audit_logger_log_denial() -> None:
    """Test logging a permission denial."""
    hass = MagicMock()
    logger = AuditLogger(hass, level=AuditLevel.ALL)
    logger._loaded = True

    logger.log_denial(
        user_id="user1",
        category="entities",
        target="light.kitchen",
        permission="control",
    )

    entries = logger.get_entries()
    assert len(entries) == 1
    assert entries[0]["action"] == "permission_denied"
    assert entries[0]["user_id"] == "user1"
    assert entries[0]["target"] == "light.kitchen"
    hass.bus.async_fire.assert_called_once()


def test_audit_logger_log_admin_action() -> None:
    """Test logging an admin action."""
    hass = MagicMock()
    logger = AuditLogger(hass, level=AuditLevel.ALL)
    logger._loaded = True

    logger.log_admin_action(
        action=AuditAction.ROLE_CREATED,
        user_id="admin1",
        context={"role_name": "Home Manager"},
    )

    entries = logger.get_entries()
    assert len(entries) == 1
    assert entries[0]["action"] == "role_created"
    assert entries[0]["context"]["role_name"] == "Home Manager"


def test_audit_logger_level_none() -> None:
    """Test that NONE level suppresses all logging."""
    hass = MagicMock()
    logger = AuditLogger(hass, level=AuditLevel.NONE)
    logger._loaded = True

    logger.log_denial("user1", "entities", "light.kitchen", "control")
    logger.log_admin_action(AuditAction.ROLE_CREATED, "admin1")

    assert len(logger.get_entries()) == 0
    hass.bus.async_fire.assert_not_called()


def test_audit_logger_level_denials_only() -> None:
    """Test that DENIALS_ONLY level only logs denials."""
    hass = MagicMock()
    logger = AuditLogger(hass, level=AuditLevel.DENIALS_ONLY)
    logger._loaded = True

    logger.log_denial("user1", "entities", "light.kitchen", "control")
    logger.log_admin_action(AuditAction.ROLE_CREATED, "admin1")

    entries = logger.get_entries()
    assert len(entries) == 1
    assert entries[0]["action"] == "permission_denied"


def test_audit_logger_level_admin_actions_only() -> None:
    """Test that ADMIN_ACTIONS_ONLY level only logs admin actions."""
    hass = MagicMock()
    logger = AuditLogger(hass, level=AuditLevel.ADMIN_ACTIONS_ONLY)
    logger._loaded = True

    logger.log_denial("user1", "entities", "light.kitchen", "control")
    logger.log_admin_action(AuditAction.ROLE_CREATED, "admin1")

    entries = logger.get_entries()
    assert len(entries) == 1
    assert entries[0]["action"] == "role_created"


def test_audit_logger_ring_buffer() -> None:
    """Test that the ring buffer caps entries."""
    hass = MagicMock()
    logger = AuditLogger(hass, max_entries=3, level=AuditLevel.ALL)
    logger._loaded = True
    logger._async_schedule_save = MagicMock()

    for i in range(5):
        logger.log_denial(f"user{i}", "entities", f"light.{i}", "control")

    entries = logger.get_entries()
    assert len(entries) == 3
    # Most recent first
    assert entries[0]["user_id"] == "user4"
    assert entries[2]["user_id"] == "user2"


def test_audit_logger_filter_by_user() -> None:
    """Test filtering entries by user ID."""
    hass = MagicMock()
    logger = AuditLogger(hass, level=AuditLevel.ALL)
    logger._loaded = True
    logger._async_schedule_save = MagicMock()

    logger.log_denial("user1", "entities", "light.a", "control")
    logger.log_denial("user2", "entities", "light.b", "control")
    logger.log_denial("user1", "entities", "light.c", "control")

    entries = logger.get_entries(user_id="user1")
    assert len(entries) == 2
    assert all(e["user_id"] == "user1" for e in entries)


def test_audit_logger_filter_by_action() -> None:
    """Test filtering entries by action."""
    hass = MagicMock()
    logger = AuditLogger(hass, level=AuditLevel.ALL)
    logger._loaded = True
    logger._async_schedule_save = MagicMock()

    logger.log_denial("user1", "entities", "light.a", "control")
    logger.log_admin_action(AuditAction.ROLE_CREATED, "admin1")

    entries = logger.get_entries(action="role_created")
    assert len(entries) == 1
    assert entries[0]["action"] == "role_created"


def test_audit_logger_limit() -> None:
    """Test limiting returned entries."""
    hass = MagicMock()
    logger = AuditLogger(hass, level=AuditLevel.ALL)
    logger._loaded = True
    logger._async_schedule_save = MagicMock()

    for i in range(10):
        logger.log_denial(f"user{i}", "entities", f"light.{i}", "control")

    entries = logger.get_entries(limit=3)
    assert len(entries) == 3


def test_audit_logger_clear() -> None:
    """Test clearing the audit log."""
    hass = MagicMock()
    logger = AuditLogger(hass, level=AuditLevel.ALL)
    logger._loaded = True
    logger._async_schedule_save = MagicMock()

    logger.log_denial("user1", "entities", "light.a", "control")
    assert len(logger.get_entries()) == 1

    logger.clear()
    assert len(logger.get_entries()) == 0


def test_audit_logger_level_setter() -> None:
    """Test changing audit level."""
    hass = MagicMock()
    logger = AuditLogger(hass)
    assert logger.level == AuditLevel.DENIALS_ONLY

    logger.level = AuditLevel.ALL
    assert logger.level == AuditLevel.ALL
