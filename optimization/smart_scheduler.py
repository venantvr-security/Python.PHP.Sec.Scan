# optimization/smart_scheduler.py
"""Smart scheduling for optimal scan performance."""

import os
from typing import List, Tuple
from pathlib import Path


class SmartScheduler:
    """Intelligently schedule file scans for optimal performance."""

    @staticmethod
    def prioritize_files(filepaths: List[str]) -> List[str]:
        """
        Prioritize files for scanning based on risk and size.

        Strategy:
        1. Large files first (utilize parallelism early)
        2. Recently modified files (likely to have changes)
        3. Files with historical vulnerabilities (if available)
        """
        file_info = []

        for filepath in filepaths:
            try:
                stat = os.stat(filepath)
                file_info.append({
                    'path': filepath,
                    'size': stat.st_size,
                    'mtime': stat.st_mtime,
                })
            except OSError:
                file_info.append({
                    'path': filepath,
                    'size': 0,
                    'mtime': 0,
                })

        # Sort: large files first, then by modification time
        file_info.sort(key=lambda x: (-x['size'], -x['mtime']))

        return [f['path'] for f in file_info]

    @staticmethod
    def batch_files(filepaths: List[str], batch_size: int = 100) -> List[List[str]]:
        """
        Batch files for processing in groups.

        Useful for database operations and plugin hooks.
        """
        return [filepaths[i:i + batch_size] for i in range(0, len(filepaths), batch_size)]

    @staticmethod
    def estimate_scan_time(num_files: int, avg_time_per_file: float, workers: int) -> float:
        """
        Estimate total scan time.

        Args:
            num_files: Number of files to scan
            avg_time_per_file: Average time per file (seconds)
            workers: Number of parallel workers

        Returns:
            Estimated time in seconds
        """
        if workers == 0:
            return float('inf')

        # Account for parallelism and overhead
        parallel_time = (num_files * avg_time_per_file) / workers
        overhead = num_files * 0.001  # 1ms overhead per file

        return parallel_time + overhead

    @staticmethod
    def filter_by_extension(filepaths: List[str], extensions: List[str] = None) -> List[str]:
        """
        Filter files by extension.

        Args:
            filepaths: List of file paths
            extensions: List of extensions (default: ['.php'])

        Returns:
            Filtered file paths
        """
        if extensions is None:
            extensions = ['.php']

        return [f for f in filepaths if any(f.endswith(ext) for ext in extensions)]

    @staticmethod
    def exclude_patterns(filepaths: List[str], patterns: List[str] = None) -> List[str]:
        """
        Exclude files matching patterns.

        Args:
            filepaths: List of file paths
            patterns: List of patterns to exclude (e.g., ['vendor/', 'test/', 'cache/'])

        Returns:
            Filtered file paths
        """
        if patterns is None:
            patterns = ['vendor/', 'node_modules/', '.git/', 'cache/', 'tmp/']

        return [
            f for f in filepaths
            if not any(pattern in f for pattern in patterns)
        ]

    @staticmethod
    def discover_php_files(
        directory: str,
        exclude_patterns: List[str] = None,
        max_size: int = 10 * 1024 * 1024  # 10MB
    ) -> List[str]:
        """
        Discover PHP files with smart filtering.

        Args:
            directory: Root directory
            exclude_patterns: Patterns to exclude
            max_size: Maximum file size in bytes

        Returns:
            List of PHP file paths
        """
        path = Path(directory)
        files = []

        for php_file in path.rglob('*.php'):
            if not php_file.is_file():
                continue

            # Check size
            try:
                if php_file.stat().st_size > max_size:
                    continue
            except OSError:
                continue

            filepath = str(php_file)

            # Check exclusions
            if exclude_patterns and any(pattern in filepath for pattern in exclude_patterns):
                continue

            files.append(filepath)

        return SmartScheduler.prioritize_files(files)


class AdaptiveWorkerPool:
    """Adaptively adjust worker pool size based on system load."""

    @staticmethod
    def get_optimal_workers() -> int:
        """
        Calculate optimal number of workers.

        Takes into account:
        - CPU count
        - System load
        - Memory availability
        """
        import os

        cpu_count = os.cpu_count() or 4

        # Cap at 32 workers max
        optimal = min(cpu_count * 2, 32)

        # Try to check system load (Unix-like systems)
        try:
            load_avg = os.getloadavg()[0]
            if load_avg > cpu_count * 0.8:
                # System under load, reduce workers
                optimal = max(cpu_count // 2, 2)
        except (AttributeError, OSError):
            # getloadavg not available (Windows)
            pass

        return max(optimal, 4)  # Minimum 4 workers
