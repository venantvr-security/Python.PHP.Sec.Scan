# cache/redis_cache.py
"""Redis-based caching for production deployments."""

import os
import pickle
from typing import Optional, Any


class RedisCache:
    """Redis cache implementation for distributed caching."""

    def __init__(self, redis_url: Optional[str] = None, ttl: int = 86400):
        self.redis_url = redis_url or os.getenv('REDIS_URL', 'redis://localhost:6379/0')
        self.ttl = ttl
        self.redis_client = None
        self._connect()

    def _connect(self):
        """Connect to Redis server."""
        try:
            import redis

            self.redis_client = redis.from_url(
                self.redis_url,
                decode_responses=False,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            # Test connection
            self.redis_client.ping()
        except ImportError:
            print("Warning: redis package not installed. Install with: pip install redis")
            self.redis_client = None
        except Exception as e:
            print(f"Warning: Could not connect to Redis: {e}")
            self.redis_client = None

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if not self.redis_client:
            return None

        try:
            value = self.redis_client.get(f"scanner:{key}")
            if value:
                return pickle.loads(value)
        except Exception as e:
            print(f"Redis get error: {e}")
        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache."""
        if not self.redis_client:
            return

        try:
            serialized = pickle.dumps(value)
            self.redis_client.setex(
                f"scanner:{key}",
                ttl or self.ttl,
                serialized
            )
        except Exception as e:
            print(f"Redis set error: {e}")

    def delete(self, key: str):
        """Delete key from cache."""
        if not self.redis_client:
            return

        try:
            self.redis_client.delete(f"scanner:{key}")
        except Exception as e:
            print(f"Redis delete error: {e}")

    def clear(self):
        """Clear all scanner cache keys."""
        if not self.redis_client:
            return

        try:
            keys = self.redis_client.keys("scanner:*")
            if keys:
                self.redis_client.delete(*keys)
        except Exception as e:
            print(f"Redis clear error: {e}")

    def get_stats(self) -> dict:
        """Get cache statistics."""
        if not self.redis_client:
            return {'enabled': False}

        try:
            info = self.redis_client.info('stats')
            return {
                'enabled': True,
                'hits': info.get('keyspace_hits', 0),
                'misses': info.get('keyspace_misses', 0),
                'keys': self.redis_client.dbsize()
            }
        except Exception as e:
            return {'enabled': True, 'error': str(e)}


class HybridCache:
    """Hybrid cache using both disk cache (fast) and Redis (distributed)."""

    def __init__(self, use_redis: bool = True):
        from cache.ast_cache import ASTCache

        self.disk_cache = ASTCache()
        self.redis_cache = RedisCache() if use_redis else None
        self.stats = {'disk_hits': 0, 'redis_hits': 0, 'misses': 0}

    def get(self, key: str) -> Optional[Any]:
        """Get from L1 (disk) then L2 (Redis)."""
        # Try disk cache first (faster)
        value = self.disk_cache.get(key)
        if value is not None:
            self.stats['disk_hits'] += 1
            return value

        # Try Redis
        if self.redis_cache:
            value = self.redis_cache.get(key)
            if value is not None:
                self.stats['redis_hits'] += 1
                # Populate disk cache for next time
                self.disk_cache.set(key, value)
                return value

        self.stats['misses'] += 1
        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set in both caches."""
        self.disk_cache.set(key, value, ttl)
        if self.redis_cache:
            self.redis_cache.set(key, value, ttl)

    def get_cache_stats(self) -> dict:
        """Get combined cache statistics."""
        stats = {
            'disk': self.disk_cache.get_stats(),
            'local_stats': self.stats
        }

        if self.redis_cache:
            stats['redis'] = self.redis_cache.get_stats()

        # Calculate hit rate
        total_requests = sum(self.stats.values())
        if total_requests > 0:
            stats['hit_rate'] = (self.stats['disk_hits'] + self.stats['redis_hits']) / total_requests

        return stats
