"""DRAKBEN Distributed State Manager
Author: @drak_ben
Description: Synchronizes agent state across distributed nodes using Redis.
             Gracefully falls back to local memory if Redis is unavailable.
"""

import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


class DistributedStateManager:
    """Manages state synchronization via Redis.
    Supports swarm mode coordination.
    """

    def __init__(
        self,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        password: str | None = None,
    ) -> None:
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.password = password
        self.redis_client = None
        self.connected = False
        # In-memory fallback when Redis is unavailable
        self._local_state: dict[str, dict[str, Any]] = {}

        # Try to connect
        self._connect()

    def _connect(self) -> None:
        """Attempt to connect to Redis."""
        try:
            import redis

            self.redis_client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                password=self.password,
                decode_responses=True,
                socket_connect_timeout=2,
            )
            # Test connection
            if self.redis_client is not None:
                self.redis_client.ping()
            self.connected = True
            logger.info(
                f"Connected to Redis Distributed State ({self.redis_host}:{self.redis_port})",
            )
        except ImportError:
            logger.warning("Redis library not installed. Running in standalone mode.")
            self.connected = False
        except Exception as e:
            logger.warning(
                "Redis connection failed: %s. Running in standalone mode.", e,
            )
            self.connected = False

    def sync_state(self, agent_id: str, state_data: dict[str, Any]) -> bool:
        """Push local state to distributed store.

        Args:
            agent_id: Unique identifier for this agent
            state_data: Dictionary representation of state

        Returns:
            True if sync successful

        """
        if not self.connected or not self.redis_client:
            # Fallback to local memory
            self._local_state[agent_id] = state_data
            return True

        try:
            key = f"drakben:agent:{agent_id}:state"
            # Serialize
            payload = json.dumps(state_data)
            # Set with expiration (hearbeat mechanics)
            self.redis_client.setex(key, 300, payload)

            # Publish update event
            self.redis_client.publish(
                "drakben:events",
                json.dumps(
                    {
                        "type": "state_update",
                        "agent_id": agent_id,
                        "timestamp": time.time(),
                    },
                ),
            )

            return True
        except Exception as e:
            logger.exception("Failed to sync state: %s", e)
            return False

    def get_swarm_state(self) -> dict[str, Any]:
        """Get states of all active agents in the swarm.

        Returns:
            Dict of agent_id -> state_data

        """
        if not self.connected or not self.redis_client:
            # Return local fallback state
            return dict(self._local_state)

        swarm_data = {}
        try:
            # Scan for all agent keys
            keys = self.redis_client.keys("drakben:agent:*:state")
            for key in keys:
                agent_id = key.split(":")[2]
                data = self.redis_client.get(key)
                if data:
                    swarm_data[agent_id] = json.loads(data)
        except Exception as e:
            logger.exception("Failed to fetch swarm state: %s", e)

        return swarm_data


# Singleton
_dsm_instance = None


def get_distributed_state_manager() -> DistributedStateManager:
    """Get singleton DistributedStateManager."""
    global _dsm_instance
    if _dsm_instance is None:
        _dsm_instance = DistributedStateManager()
    return _dsm_instance
