# optimization/profiler.py
"""Performance profiling utilities."""

import time
import functools
import logging
from typing import Callable, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


class PerformanceProfiler:
    """Simple performance profiler for tracking execution times."""

    def __init__(self):
        self.timings = defaultdict(list)
        self.call_counts = defaultdict(int)

    def profile(self, func: Callable) -> Callable:
        """Decorator to profile function execution time."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            start = time.perf_counter()
            result = func(*args, **kwargs)
            elapsed = time.perf_counter() - start

            func_name = f"{func.__module__}.{func.__name__}"
            self.timings[func_name].append(elapsed)
            self.call_counts[func_name] += 1

            return result
        return wrapper

    def get_stats(self) -> dict:
        """Get profiling statistics."""
        stats = {}
        for func_name, times in self.timings.items():
            stats[func_name] = {
                'calls': self.call_counts[func_name],
                'total_time': sum(times),
                'avg_time': sum(times) / len(times) if times else 0,
                'min_time': min(times) if times else 0,
                'max_time': max(times) if times else 0,
            }
        return stats

    def print_stats(self):
        """Print profiling statistics."""
        stats = self.get_stats()
        print("\n" + "=" * 80)
        print("PERFORMANCE PROFILE")
        print("=" * 80)
        print(f"{'Function':<50} {'Calls':<10} {'Total(s)':<12} {'Avg(ms)':<12}")
        print("-" * 80)

        for func_name, data in sorted(stats.items(), key=lambda x: -x[1]['total_time']):
            print(f"{func_name:<50} {data['calls']:<10} {data['total_time']:<12.3f} {data['avg_time']*1000:<12.3f}")

    def reset(self):
        """Reset all profiling data."""
        self.timings.clear()
        self.call_counts.clear()


# Global profiler instance
profiler = PerformanceProfiler()
