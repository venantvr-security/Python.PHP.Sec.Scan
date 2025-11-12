# cache/ast_cache.py
import logging
import os
from typing import Any, Optional

from diskcache import Cache

logger = logging.getLogger(__name__)


class ASTCache:
    """Optimized cache for AST analysis results with LRU eviction."""

    def __init__(self, cache_dir: Optional[str] = None, ttl: int = 86400, size_limit: int = 1024**3):
        """Initialize cache with size limit."""
        if cache_dir is None:
            cache_dir = os.getenv('CACHE_DIR', './cache_data')

        self.cache_dir = cache_dir
        self.ttl = ttl
        self.cache = Cache(cache_dir, size_limit=size_limit, eviction_policy='least-recently-used')

        logger.info(f"AST Cache: {cache_dir} (limit: {size_limit // 1024**2}MB)")

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
        """Get detailed cache statistics."""
        try:
            stats_tuple = self.cache.stats(enable=True)
            # diskcache.Cache.stats() returns (hits, misses)
            hits, misses = stats_tuple if isinstance(stats_tuple, tuple) else (0, 0)
            return {
                'entries': len(self.cache),
                'size': self.cache.volume(),
                'hits': hits,
                'misses': misses,
                'hit_rate': hits / max(hits + misses, 1),
                'directory': self.cache_dir,
            }
        except Exception as e:
            logger.error(f"Cache stats error: {e}")
            return {'entries': len(self.cache), 'size': 0, 'directory': self.cache_dir}

    def close(self):
        """Close cache connection."""
        self.cache.close()
