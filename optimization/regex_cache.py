# optimization/regex_cache.py
"""Regex pattern caching for performance."""

import re
from functools import lru_cache
from typing import Pattern


@lru_cache(maxsize=256)
def get_compiled_pattern(pattern: str, flags: int = 0) -> Pattern:
    """Get compiled regex pattern with caching."""
    return re.compile(pattern, flags)


@lru_cache(maxsize=512)
def cached_match(pattern: str, text: str, flags: int = 0) -> bool:
    """Cached regex match."""
    compiled = get_compiled_pattern(pattern, flags)
    return compiled.search(text) is not None


@lru_cache(maxsize=512)
def cached_findall(pattern: str, text: str, flags: int = 0) -> tuple:
    """Cached regex findall (returns tuple for hashability)."""
    compiled = get_compiled_pattern(pattern, flags)
    return tuple(compiled.findall(text))


def clear_regex_cache():
    """Clear all regex caches."""
    get_compiled_pattern.cache_clear()
    cached_match.cache_clear()
    cached_findall.cache_clear()
