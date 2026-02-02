"""Tests for Sandbox Manager module.
These tests work whether Docker is installed or not.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sandbox_manager import (
    ContainerStatus,
    SandboxManager,
    get_sandbox_manager,
    is_sandbox_available,
)


class TestSandboxManagerBasic(unittest.TestCase):
    """Basic tests that work without Docker."""

    def test_initialization(self) -> None:
        """Test manager initialization."""
        manager = SandboxManager()
        if manager is None:
            msg = "manager is not None"
            raise AssertionError(msg)
        if manager.image != "python:3.11-slim":
            msg = 'manager.image == "python:3.11-slim"'
            raise AssertionError(msg)
        if manager.memory_limit != "512m":
            msg = 'manager.memory_limit == "512m"'
            raise AssertionError(msg)
        if len(manager.active_containers) != 0:
            msg = "len(manager.active_containers) == 0"
            raise AssertionError(msg)

    def test_custom_initialization(self) -> None:
        """Test manager with custom parameters."""
        manager = SandboxManager(
            image="custom:latest",
            memory_limit="1g",
            cpu_limit="2.0",
        )
        if manager.image != "custom:latest":
            msg = 'manager.image == "custom:latest"'
            raise AssertionError(msg)
        if manager.memory_limit != "1g":
            msg = 'manager.memory_limit == "1g"'
            raise AssertionError(msg)
        if manager.cpu_limit != "2.0":
            msg = 'manager.cpu_limit == "2.0"'
            raise AssertionError(msg)

    def test_is_available_returns_bool(self) -> None:
        """Test is_available returns boolean."""
        manager = SandboxManager()
        result = manager.is_available()
        if not isinstance(result, bool):
            msg = "isinstance(result, bool)"
            raise AssertionError(msg)

    def test_singleton_function(self) -> None:
        """Test get_sandbox_manager returns same instance."""
        manager1 = get_sandbox_manager()
        manager2 = get_sandbox_manager()
        if manager1 is not manager2:
            msg = "manager1 is manager2"
            raise AssertionError(msg)

    def test_module_level_availability_check(self) -> None:
        """Test is_sandbox_available function."""
        result = is_sandbox_available()
        if not isinstance(result, bool):
            msg = "isinstance(result, bool)"
            raise AssertionError(msg)

    def test_container_status_enum(self) -> None:
        """Test ContainerStatus enum values."""
        if ContainerStatus.PENDING.value != "pending":
            msg = 'ContainerStatus.PENDING.value == "pending"'
            raise AssertionError(msg)
        if ContainerStatus.RUNNING.value != "running":
            msg = 'ContainerStatus.RUNNING.value == "running"'
            raise AssertionError(msg)
        if ContainerStatus.STOPPED.value != "stopped":
            msg = 'ContainerStatus.STOPPED.value == "stopped"'
            raise AssertionError(msg)
        if ContainerStatus.REMOVED.value != "removed":
            msg = 'ContainerStatus.REMOVED.value == "removed"'
            raise AssertionError(msg)
        if ContainerStatus.ERROR.value != "error":
            msg = 'ContainerStatus.ERROR.value == "error"'
            raise AssertionError(msg)

    def test_list_active_containers_empty(self) -> None:
        """Test list_active_containers returns empty list initially."""
        manager = SandboxManager()
        containers = manager.list_active_containers()
        if not isinstance(containers, list):
            msg = "isinstance(containers, list)"
            raise AssertionError(msg)
        if len(containers) != 0:
            msg = "len(containers) == 0"
            raise AssertionError(msg)

    def test_cleanup_all_on_empty(self) -> None:
        """Test cleanup_all works on empty manager."""
        manager = SandboxManager()
        cleaned = manager.cleanup_all()
        if cleaned != 0:
            msg = "cleaned == 0"
            raise AssertionError(msg)

    def test_get_container_status_nonexistent(self) -> None:
        """Test get_container_status for non-existent container."""
        manager = SandboxManager()
        status = manager.get_container_status("nonexistent-id")
        if status != ContainerStatus.REMOVED:
            msg = "status == ContainerStatus.REMOVED"
            raise AssertionError(msg)


class TestSandboxManagerWithoutDocker(unittest.TestCase):
    """Tests for graceful handling when Docker is unavailable."""

    def test_create_sandbox_without_docker(self) -> None:
        """Test create_sandbox fails gracefully without Docker."""
        manager = SandboxManager()
        if not manager.is_available():
            result = manager.create_sandbox("test-container")
            if result is not None:
                msg = "result is None"
                raise AssertionError(msg)

    def test_execute_in_sandbox_invalid_container(self) -> None:
        """Test execute_in_sandbox with invalid container ID."""
        manager = SandboxManager()
        result = manager.execute_in_sandbox("invalid-id", "echo test")
        if result.success:
            msg = "not result.success"
            raise AssertionError(msg)
        if result.exit_code != -1:
            msg = "result.exit_code == -1"
            raise AssertionError(msg)
        if "not found" not in result.stderr.lower():
            msg = '"not found" in result.stderr.lower()'
            raise AssertionError(msg)

    def test_cleanup_sandbox_invalid_container(self) -> None:
        """Test cleanup_sandbox with invalid container ID."""
        manager = SandboxManager()
        result = manager.cleanup_sandbox("invalid-id")
        if result:
            msg = "not result"
            raise AssertionError(msg)


if __name__ == "__main__":
    unittest.main()
