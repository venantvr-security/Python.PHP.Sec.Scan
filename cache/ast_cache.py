# cache/ast_cache.py
import os
import logging
from typing import Any, Optional
from diskcache import Cache

logger = logging.getLogger(__name__)


class ASTCache:
    """
    Cache for AST analysis results.

    Uses diskcache for persistent, disk-based caching.
    Can be swapped to Redis for distributed caching.
    """

    def __init__(self, cache_dir: Optional[str] = None, ttl: int = 86400):
        """
        Initialize cache.

        Args:
            cache_dir: Directory for cache storage (default: ./cache_data)
            ttl: Time-to-live in seconds (default: 24 hours)
        """
        if cache_dir is None:
            cache_dir = os.getenv('CACHE_DIR', './cache_data')

        self.cache_dir = cache_dir
        self.ttl = ttl
        self.cache = Cache(cache_dir)

        logger.info(f"AST Cache initialized: {cache_dir}")

    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key (typically file hash)

        Returns:
            Cached value or None if not found/expired
        """
        try:
            value = self.cache.get(key)
            if value is not None:
                logger.debug(f"Cache hit: {key}")
            return value
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Set value in cache.

        Args:
            key: Cache key (typically file hash)
            value: Value to cache (scan results)
            ttl: Time-to-live override

        Returns:
            True if successful
        """
        try:
            expire_time = ttl if ttl is not None else self.ttl
            self.cache.set(key, value, expire=expire_time)
            logger.debug(f"Cache set: {key}")
            return True
        except Exception as e:
            logger.error(f"Cache set error: {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete key from cache."""
        try:
            return self.cache.delete(key)
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
            return False

    def clear(self) -> bool:
        """Clear all cache entries."""
        try:
            self.cache.clear()
            logger.info("Cache cleared")
            return True
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
            return False

    def stats(self) -> dict:
        """Get cache statistics."""
        try:
            return {
                'size': len(self.cache),
                'volume': self.cache.volume(),
                'directory': self.cache_dir,
            }
        except Exception as e:
            logger.error(f"Cache stats error: {e}")
            return {}

    def close(self):
        """Close cache connection."""
        self.cache.close()
