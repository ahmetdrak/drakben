"""DRAKBEN Distributed State Manager
Author: @drak_ben
Description: Synchronizes agent state across distributed nodes using Redis.
             Gracefully falls back to local memory if Redis is unavailable.
"""

import logging
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
                "Connected to Redis Distributed State (%s:%s)",
                self.redis_host, self.redis_port,
            )
        except ImportError:
            logger.warning("Redis library not installed. Running in standalone mode.")
            self.connected = False
        except Exception as e:
            logger.warning(
                "Redis connection failed: %s. Running in standalone mode.", e,
            )
            self.connected = False
