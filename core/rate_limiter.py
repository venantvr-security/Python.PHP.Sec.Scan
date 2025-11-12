"""Rate limiting and throttling for API and scanner."""

import time
from typing import Optional, Dict
from collections import deque
from threading import Lock
import hashlib

from core.exceptions import RateLimitError


class TokenBucket:
    """Token bucket algorithm for rate limiting."""

    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.

        Args:
            capacity: Maximum number of tokens
            refill_rate: Tokens added per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = Lock()

    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens.

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if successful, False if not enough tokens
        """
        with self.lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            return False

    def _refill(self):
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill

        new_tokens = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_refill = now

    def available_tokens(self) -> int:
        """Get number of available tokens."""
        with self.lock:
            self._refill()
            return int(self.tokens)


class SlidingWindowRateLimiter:
    """Sliding window rate limiter."""

    def __init__(self, max_requests: int, window_seconds: int):
        """
        Initialize sliding window rate limiter.

        Args:
            max_requests: Maximum requests per window
            window_seconds: Window size in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = {}
        self.lock = Lock()

    def is_allowed(self, key: str) -> bool:
        """
        Check if request is allowed.

        Args:
            key: Client identifier (e.g., IP address)

        Returns:
            True if allowed, False if rate limited
        """
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds

            # Initialize if new key
            if key not in self.requests:
                self.requests[key] = deque()

            # Remove old timestamps
            while self.requests[key] and self.requests[key][0] < cutoff:
                self.requests[key].popleft()

            # Check limit
            if len(self.requests[key]) >= self.max_requests:
                return False

            # Add current timestamp
            self.requests[key].append(now)
            return True

    def get_remaining(self, key: str) -> int:
        """Get remaining requests for key."""
        with self.lock:
            if key not in self.requests:
                return self.max_requests

            now = time.time()
            cutoff = now - self.window_seconds

            # Count valid requests
            valid_requests = sum(1 for ts in self.requests[key] if ts >= cutoff)
            return max(0, self.max_requests - valid_requests)

    def reset(self, key: str):
        """Reset rate limit for key."""
        with self.lock:
            if key in self.requests:
                del self.requests[key]


class RateLimiter:
    """Main rate limiter with multiple strategies."""

    def __init__(self, strategy: str = 'token_bucket', **kwargs):
        """
        Initialize rate limiter.

        Args:
            strategy: 'token_bucket' or 'sliding_window'
            **kwargs: Strategy-specific parameters
        """
        self.strategy = strategy

        if strategy == 'token_bucket':
            capacity = kwargs.get('capacity', 100)
            refill_rate = kwargs.get('refill_rate', 10.0)
            self.limiter = TokenBucket(capacity, refill_rate)
        elif strategy == 'sliding_window':
            max_requests = kwargs.get('max_requests', 100)
            window_seconds = kwargs.get('window_seconds', 60)
            self.limiter = SlidingWindowRateLimiter(max_requests, window_seconds)
        else:
            raise ValueError(f"Unknown strategy: {strategy}")

    def check_limit(self, identifier: str) -> bool:
        """
        Check if request is within rate limit.

        Args:
            identifier: Client identifier

        Returns:
            True if allowed

        Raises:
            RateLimitError: If rate limit exceeded
        """
        if self.strategy == 'token_bucket':
            if not self.limiter.consume():
                raise RateLimitError(
                    "Rate limit exceeded",
                    {'available_tokens': self.limiter.available_tokens()}
                )
        elif self.strategy == 'sliding_window':
            if not self.limiter.is_allowed(identifier):
                remaining = self.limiter.get_remaining(identifier)
                raise RateLimitError(
                    "Rate limit exceeded",
                    {'remaining': remaining}
                )

        return True

    @staticmethod
    def generate_key(ip: str, user_id: Optional[str] = None) -> str:
        """
        Generate rate limit key.

        Args:
            ip: Client IP address
            user_id: Optional user identifier

        Returns:
            Rate limit key
        """
        if user_id:
            raw = f"{ip}:{user_id}"
        else:
            raw = ip

        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class ScanThrottler:
    """Throttle scan operations to prevent resource exhaustion."""

    def __init__(self, max_concurrent: int = 10, max_files_per_second: float = 100):
        """
        Initialize scan throttler.

        Args:
            max_concurrent: Maximum concurrent scans
            max_files_per_second: Maximum files processed per second
        """
        self.max_concurrent = max_concurrent
        self.max_files_per_second = max_files_per_second

        self.active_scans = 0
        self.last_file_time = time.time()
        self.lock = Lock()

    def acquire_scan_slot(self, timeout: float = 10.0) -> bool:
        """
        Acquire slot for scan operation.

        Args:
            timeout: Maximum wait time in seconds

        Returns:
            True if acquired, False if timeout
        """
        start = time.time()

        while time.time() - start < timeout:
            with self.lock:
                if self.active_scans < self.max_concurrent:
                    self.active_scans += 1
                    return True

            time.sleep(0.1)

        return False

    def release_scan_slot(self):
        """Release scan slot."""
        with self.lock:
            if self.active_scans > 0:
                self.active_scans -= 1

    def throttle_file_processing(self):
        """Throttle file processing rate."""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_file_time
            min_interval = 1.0 / self.max_files_per_second

            if elapsed < min_interval:
                sleep_time = min_interval - elapsed
                time.sleep(sleep_time)

            self.last_file_time = time.time()

    def get_stats(self) -> Dict[str, any]:
        """Get throttler statistics."""
        with self.lock:
            return {
                'active_scans': self.active_scans,
                'max_concurrent': self.max_concurrent,
                'max_files_per_second': self.max_files_per_second,
            }
