"""
Tests for Sandbox Manager module.
These tests work whether Docker is installed or not.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sandbox_manager import (
    SandboxManager,
    ContainerStatus,
    ContainerInfo,
    ExecutionResult,
    is_sandbox_available,
    get_sandbox_manager,
)


class TestSandboxManagerBasic(unittest.TestCase):
    """Basic tests that work without Docker"""
    
    def test_import(self):
        """Test that module imports correctly"""
        self.assertIsNotNone(SandboxManager)
        self.assertIsNotNone(ContainerStatus)
        self.assertIsNotNone(ContainerInfo)
        self.assertIsNotNone(ExecutionResult)
    
    def test_initialization(self):
        """Test manager initialization"""
        manager = SandboxManager()
        self.assertIsNotNone(manager)
        self.assertEqual(manager.image, "python:3.11-slim")
        self.assertEqual(manager.memory_limit, "512m")
        self.assertEqual(len(manager.active_containers), 0)
    
    def test_custom_initialization(self):
        """Test manager with custom parameters"""
        manager = SandboxManager(
            image="custom:latest",
            memory_limit="1g",
            cpu_limit="2.0"
        )
        self.assertEqual(manager.image, "custom:latest")
        self.assertEqual(manager.memory_limit, "1g")
        self.assertEqual(manager.cpu_limit, "2.0")
    
    def test_is_available_returns_bool(self):
        """Test is_available returns boolean"""
        manager = SandboxManager()
        result = manager.is_available()
        self.assertIsInstance(result, bool)
    
    def test_singleton_function(self):
        """Test get_sandbox_manager returns same instance"""
        manager1 = get_sandbox_manager()
        manager2 = get_sandbox_manager()
        self.assertIs(manager1, manager2)
    
    def test_module_level_availability_check(self):
        """Test is_sandbox_available function"""
        result = is_sandbox_available()
        self.assertIsInstance(result, bool)
    
    def test_container_status_enum(self):
        """Test ContainerStatus enum values"""
        self.assertEqual(ContainerStatus.PENDING.value, "pending")
        self.assertEqual(ContainerStatus.RUNNING.value, "running")
        self.assertEqual(ContainerStatus.STOPPED.value, "stopped")
        self.assertEqual(ContainerStatus.REMOVED.value, "removed")
        self.assertEqual(ContainerStatus.ERROR.value, "error")
    
    def test_list_active_containers_empty(self):
        """Test list_active_containers returns empty list initially"""
        manager = SandboxManager()
        containers = manager.list_active_containers()
        self.assertIsInstance(containers, list)
        self.assertEqual(len(containers), 0)
    
    def test_cleanup_all_on_empty(self):
        """Test cleanup_all works on empty manager"""
        manager = SandboxManager()
        cleaned = manager.cleanup_all()
        self.assertEqual(cleaned, 0)
    
    def test_get_container_status_nonexistent(self):
        """Test get_container_status for non-existent container"""
        manager = SandboxManager()
        status = manager.get_container_status("nonexistent-id")
        self.assertEqual(status, ContainerStatus.REMOVED)


class TestSandboxManagerWithoutDocker(unittest.TestCase):
    """Tests for graceful handling when Docker is unavailable"""
    
    def test_create_sandbox_without_docker(self):
        """Test create_sandbox fails gracefully without Docker"""
        manager = SandboxManager()
        if not manager.is_available():
            result = manager.create_sandbox("test-container")
            self.assertIsNone(result)
    
    def test_execute_in_sandbox_invalid_container(self):
        """Test execute_in_sandbox with invalid container ID"""
        manager = SandboxManager()
        result = manager.execute_in_sandbox("invalid-id", "echo test")
        self.assertFalse(result.success)
        self.assertEqual(result.exit_code, -1)
        self.assertIn("not found", result.stderr.lower())
    
    def test_cleanup_sandbox_invalid_container(self):
        """Test cleanup_sandbox with invalid container ID"""
        manager = SandboxManager()
        result = manager.cleanup_sandbox("invalid-id")
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
