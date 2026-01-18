"""
Test suite for core.executor module
"""

import pytest
from unittest.mock import Mock, patch
from core.executor import Executor


class TestExecutor:
    """Test cases for Executor class"""
    
    def test_executor_initialization(self):
        """Test executor initializes correctly"""
        executor = Executor()
        assert executor is not None
        assert hasattr(executor, 'run')  # Changed from 'execute' to 'run'
    
    @patch('subprocess.run')
    def test_run_simple_command(self, mock_run):
        """Test running a simple command"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Command executed successfully",
            stderr=""
        )
        
        executor = Executor()
        result = executor.run("echo test")  # Changed from execute to run
        
        assert result is not None
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_run_command_failure(self, mock_run):
        """Test handling command execution failure"""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Command failed"
        )
        
        executor = Executor()
        result = executor.run("invalid_command")  # Changed from execute to run
        
        # Should handle error gracefully
        assert result is not None
    
    @patch('subprocess.run')
    def test_run_chain(self, mock_run):
        """Test running command chain"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Success",
            stderr=""
        )
        
        executor = Executor()
        chain = [
            {"step": "scan", "command": "nmap -sV 192.168.1.1"},
            {"step": "enumerate", "command": "enum4linux 192.168.1.1"}
        ]
        
        results = executor.run_chain(chain)
        
        assert results is not None
        assert len(results) == 2
        assert all("output" in r for r in results)
