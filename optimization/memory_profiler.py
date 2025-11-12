#!/usr/bin/env python3
"""Memory profiling utilities."""

import linecache
import tracemalloc
from typing import List, Tuple


def start_profiling():
    """Start memory profiling."""
    tracemalloc.start()


def get_top_memory_usage(limit: int = 10) -> List[Tuple[str, int]]:
    """Get top memory consuming code locations."""
    snapshot = tracemalloc.take_snapshot()
    top_stats = snapshot.statistics('lineno')

    results = []
    for stat in top_stats[:limit]:
        frame = stat.traceback[0]
        results.append((
            f"{frame.filename}:{frame.lineno}",
            stat.size // 1024  # Convert to KB
        ))

    return results


def display_top(limit: int = 10):
    """Display top memory usage."""
    snapshot = tracemalloc.take_snapshot()
    top_stats = snapshot.statistics('lineno')

    print(f"\nTop {limit} memory allocations:")
    for index, stat in enumerate(top_stats[:limit], 1):
        frame = stat.traceback[0]
        print(f"#{index}: {frame.filename}:{frame.lineno}: {stat.size / 1024:.1f} KB")
        line = linecache.getline(frame.filename, frame.lineno).strip()
        if line:
            print(f"    {line}")


def compare_snapshots(snapshot1, snapshot2, limit: int = 10):
    """Compare two memory snapshots."""
    top_stats = snapshot2.compare_to(snapshot1, 'lineno')

    print(f"\nTop {limit} memory differences:")
    for stat in top_stats[:limit]:
        print(f"{stat}")


def stop_profiling():
    """Stop memory profiling."""
    tracemalloc.stop()
