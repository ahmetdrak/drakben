"""DRAKBEN Distributed State Manager
Author: @drak_ben
Description: Synchronizes agent state across distributed nodes using Redis.
             Gracefully falls back to local memory if Redis is unavailable.
"""

import json
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
                self.redis_host,
                self.redis_port,
            )
        except ImportError:
            logger.warning("Redis library not installed. Running in standalone mode.")
            self.connected = False
        except OSError as e:
            logger.warning(
                "Redis connection failed: %s. Running in standalone mode.",
                e,
            )
            self.connected = False

    def get_state(self, key: str, namespace: str = "global") -> Any | None:
        """Get state value by key.

        Args:
            key: The state key to retrieve.
            namespace: Namespace prefix for key isolation.

        Returns:
            The stored value, or None if not found.
        """
        full_key = f"drakben:{namespace}:{key}"
        if self.connected and self.redis_client:
            try:
                raw = self.redis_client.get(full_key)
                if raw is not None:
                    try:
                        return json.loads(raw)
                    except (json.JSONDecodeError, TypeError):
                        return raw
                return None
            except OSError as e:
                logger.warning("Redis get failed for %s: %s", full_key, e)
        # Fallback to local
        ns = self._local_state.get(namespace, {})
        return ns.get(key)

    def set_state(self, key: str, value: Any, namespace: str = "global", ttl: int | None = None) -> bool:
        """Set state value.

        Args:
            key: The state key.
            value: The value to store (will be JSON-serialized for Redis).
            namespace: Namespace prefix.
            ttl: Optional time-to-live in seconds (Redis only).

        Returns:
            True if stored successfully.
        """
        full_key = f"drakben:{namespace}:{key}"
        redis_success = False
        if self.connected and self.redis_client:
            try:
                serialized = json.dumps(value)
                if ttl:
                    self.redis_client.setex(full_key, ttl, serialized)
                else:
                    self.redis_client.set(full_key, serialized)
                redis_success = True
            except (OSError, TypeError) as e:
                logger.warning("Redis set failed for %s: %s", full_key, e)
        # Always update local state as fallback/cache
        if namespace not in self._local_state:
            self._local_state[namespace] = {}
        self._local_state[namespace][key] = value
        return redis_success or not self.connected

    def delete_state(self, key: str, namespace: str = "global") -> bool:
        """Delete a state key.

        Args:
            key: The key to delete.
            namespace: Namespace prefix.

        Returns:
            True if deleted.
        """
        full_key = f"drakben:{namespace}:{key}"
        if self.connected and self.redis_client:
            try:
                self.redis_client.delete(full_key)
            except OSError as e:
                logger.warning("Redis delete failed for %s: %s", full_key, e)
        ns = self._local_state.get(namespace, {})
        ns.pop(key, None)
        return True

    def get_all_keys(self, namespace: str = "global") -> list[str]:
        """List all keys in a namespace.

        Args:
            namespace: Namespace to list.

        Returns:
            List of key names.
        """
        prefix = f"drakben:{namespace}:"
        if self.connected and self.redis_client:
            try:
                raw_keys = list(self.redis_client.scan_iter(match=f"{prefix}*"))
                return [k.replace(prefix, "") for k in raw_keys]
            except OSError as e:
                logger.warning("Redis keys failed: %s", e)
        return list(self._local_state.get(namespace, {}).keys())
