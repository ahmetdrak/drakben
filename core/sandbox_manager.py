"""
DRAKBEN Sandbox Manager
Author: @drak_ben
Description: Docker-based isolated execution environment for safe operation

This module provides:
- Isolated container creation for attack operations
- Secure command execution within containers
- Clean-up without leaving traces on host system
- Graceful fallback when Docker is unavailable
"""

import logging
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Setup logger
logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

# Default Docker image for sandbox operations
DEFAULT_SANDBOX_IMAGE = "python:3.11-slim"

# Kali Linux image for full pentest toolkit
KALI_SANDBOX_IMAGE = "kalilinux/kali-rolling"

# Container resource limits
DEFAULT_MEMORY_LIMIT = "512m"
DEFAULT_CPU_LIMIT = "1.0"

# Timeout for container operations (seconds)
CONTAINER_TIMEOUT = 300


# =============================================================================
# DATA CLASSES
# =============================================================================


class ContainerStatus(Enum):
    """Status of a sandbox container"""

    PENDING = "pending"
    RUNNING = "running"
    STOPPED = "stopped"
    REMOVED = "removed"
    ERROR = "error"


@dataclass
class ContainerInfo:
    """Information about a sandbox container"""

    container_id: str
    name: str
    image: str
    status: ContainerStatus
    created_at: float
    ports: dict[str, str] = field(default_factory=dict)
    volumes: list[str] = field(default_factory=list)


@dataclass
class ExecutionResult:
    """Result of command execution in sandbox"""

    success: bool
    stdout: str
    stderr: str
    exit_code: int
    duration: float


# =============================================================================
# SANDBOX MANAGER
# =============================================================================


class SandboxManager:
    """
    Docker-based sandbox manager for isolated command execution.

    Features:
    - Container lifecycle management (create, execute, cleanup)
    - Resource limits for safety
    - Automatic cleanup on failure
    - Graceful fallback when Docker unavailable

    Usage:
        manager = SandboxManager()
        if manager.is_available():
            container = manager.create_sandbox("pentest-session")
            result = manager.execute_in_sandbox(container.container_id, "nmap -sV target.com")
            manager.cleanup_sandbox(container.container_id)
    """

    def __init__(
        self,
        image: str = DEFAULT_SANDBOX_IMAGE,
        memory_limit: str = DEFAULT_MEMORY_LIMIT,
        cpu_limit: str = DEFAULT_CPU_LIMIT,
    ):
        """
        Initialize SandboxManager.

        Args:
            image: Docker image to use for containers
            memory_limit: Memory limit for containers (e.g., "512m")
            cpu_limit: CPU limit for containers (e.g., "1.0")
        """
        self.image = image
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.active_containers: dict[str, ContainerInfo] = {}
        self._docker_available: bool | None = None
        self._docker_client: Any | None = None

        logger.info(f"SandboxManager initialized with image: {image}")

    def is_available(self) -> bool:
        """
        Check if Docker is available on the system.

        Returns:
            True if Docker is installed and running, False otherwise
        """
        if self._docker_available is not None:
            return self._docker_available

        self._docker_available = self._check_docker()
        return self._docker_available

    @staticmethod
    def _check_docker() -> bool:
        """
        Internal method to check Docker availability.

        Returns:
            True if Docker is available
        """
        try:
            result = subprocess.run(
                ["docker", "version"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                logger.info("Docker is available")
                return True
            logger.warning(f"Docker check failed: {result.stderr}")
            return False
        except FileNotFoundError:
            logger.warning("Docker not found in PATH")
            return False
        except subprocess.TimeoutExpired:
            logger.warning("Docker check timed out")
            return False
        except Exception as e:
            logger.warning(f"Docker check error: {e}")
            return False

    def _get_docker_client(self) -> Any | None:
        """
        Get or create Docker client.

        Returns:
            Docker client or None if unavailable
        """
        if self._docker_client is not None:
            return self._docker_client

        try:
            import docker

            self._docker_client = docker.from_env()
            return self._docker_client
        except ImportError:
            logger.warning("docker-py not installed. Install with: pip install docker")
            return None
        except Exception as e:
            logger.warning(f"Failed to create Docker client: {e}")
            return None

    def create_sandbox(
        self,
        name: str,
        image: str | None = None,
        volumes: list[str] | None = None,
        environment: dict[str, str] | None = None,
    ) -> ContainerInfo | None:
        """
        Create a new sandbox container.

        Args:
            name: Unique name for the container
            image: Docker image (uses default if None)
            volumes: Volume mounts (e.g., ["/host/path:/container/path"])
            environment: Environment variables

        Returns:
            ContainerInfo if successful, None if failed
        """
        if not self.is_available():
            logger.error("Docker not available, cannot create sandbox")
            return None

        client = self._get_docker_client()
        if client is None:
            return None

        container_image = image or self.image
        container_name = f"drakben-sandbox-{name}-{int(time.time())}"

        try:
            container = client.containers.run(
                container_image,
                command="tail -f /dev/null",  # Keep container running
                name=container_name,
                detach=True,
                mem_limit=self.memory_limit,
                cpu_period=100000,
                cpu_quota=int(float(self.cpu_limit) * 100000),
                volumes=volumes or [],
                environment=environment or {},
                network_mode="bridge",
                auto_remove=False,  # We manually remove for cleanup verification
            )

            info = ContainerInfo(
                container_id=container.id,
                name=container_name,
                image=container_image,
                status=ContainerStatus.RUNNING,
                created_at=time.time(),
                volumes=volumes or [],
            )

            self.active_containers[container.id] = info
            logger.info(
                f"Created sandbox container: {container_name} ({container.id[:12]})"
            )

            return info

        except Exception as e:
            logger.error(f"Failed to create sandbox: {e}")
            return None

    def execute_in_sandbox(
        self,
        container_id: str,
        command: str,
        timeout: int = CONTAINER_TIMEOUT,
        workdir: str | None = None,
    ) -> ExecutionResult:
        """
        Execute command inside a sandbox container.

        Args:
            container_id: ID of the container
            command: Command to execute
            timeout: Execution timeout in seconds
            workdir: Working directory inside container

        Returns:
            ExecutionResult with stdout, stderr, and exit code
        """
        start_time = time.time()

        if container_id not in self.active_containers:
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="Container not found or not managed by this manager",
                exit_code=-1,
                duration=0.0,
            )

        client = self._get_docker_client()
        if client is None:
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="Docker client unavailable",
                exit_code=-1,
                duration=0.0,
            )

        try:
            container = client.containers.get(container_id)

            exec_result = container.exec_run(
                cmd=command, workdir=workdir, demux=True, tty=False
            )

            duration = time.time() - start_time
            stdout_data, stderr_data = exec_result.output or (b"", b"")

            stdout = (
                stdout_data.decode("utf-8", errors="replace") if stdout_data else ""
            )
            stderr = (
                stderr_data.decode("utf-8", errors="replace") if stderr_data else ""
            )

            success = exec_result.exit_code == 0

            logger.debug(
                f"Sandbox exec [{container_id[:12]}]: {command[:50]}... -> exit={exec_result.exit_code}"
            )

            return ExecutionResult(
                success=success,
                stdout=stdout,
                stderr=stderr,
                exit_code=exec_result.exit_code,
                duration=duration,
            )

        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Sandbox execution failed: {e}")
            return ExecutionResult(
                success=False, stdout="", stderr=str(e), exit_code=-1, duration=duration
            )

    def cleanup_sandbox(self, container_id: str, force: bool = True) -> bool:
        """
        Remove sandbox container and clean up resources.

        Args:
            container_id: ID of the container to remove
            force: Force removal even if running

        Returns:
            True if cleanup successful
        """
        if container_id not in self.active_containers:
            logger.warning(f"Container {container_id[:12]} not in active containers")
            return False

        client = self._get_docker_client()
        if client is None:
            return False

        try:
            container = client.containers.get(container_id)
            container.remove(force=force)

            del self.active_containers[container_id]
            logger.info(f"Cleaned up sandbox container: {container_id[:12]}")

            return True

        except Exception as e:
            logger.error(f"Failed to cleanup sandbox {container_id[:12]}: {e}")
            return False

    def cleanup_all(self) -> int:
        """
        Remove all active sandbox containers.

        Returns:
            Number of containers cleaned up
        """
        cleaned = 0
        container_ids = list(self.active_containers.keys())

        for container_id in container_ids:
            if self.cleanup_sandbox(container_id):
                cleaned += 1

        logger.info(f"Cleaned up {cleaned} sandbox containers")
        return cleaned

    def get_container_status(self, container_id: str) -> ContainerStatus:
        """
        Get current status of a container.

        Args:
            container_id: ID of the container

        Returns:
            ContainerStatus enum value
        """
        if container_id not in self.active_containers:
            return ContainerStatus.REMOVED

        client = self._get_docker_client()
        if client is None:
            return ContainerStatus.ERROR

        try:
            container = client.containers.get(container_id)
            status_map = {
                "running": ContainerStatus.RUNNING,
                "exited": ContainerStatus.STOPPED,
                "created": ContainerStatus.PENDING,
            }
            return status_map.get(container.status, ContainerStatus.ERROR)

        except Exception:
            return ContainerStatus.ERROR

    def list_active_containers(self) -> list[ContainerInfo]:
        """
        List all active sandbox containers.

        Returns:
            List of ContainerInfo objects
        """
        return list(self.active_containers.values())


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================


def get_sandbox_manager() -> SandboxManager:
    """
    Get singleton SandboxManager instance.

    Returns:
        SandboxManager instance
    """
    global _sandbox_manager
    if "_sandbox_manager" not in globals() or _sandbox_manager is None:
        _sandbox_manager = SandboxManager()
    return _sandbox_manager


def is_sandbox_available() -> bool:
    """
    Quick check if sandbox functionality is available.

    Returns:
        True if Docker is available and working
    """
    return get_sandbox_manager().is_available()
