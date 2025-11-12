# workers/parallel_scanner.py
import hashlib
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable

from analysis.taint_tracker import TaintTracker, PARSER
from cache.ast_cache import ASTCache
from workers.progress_tracker import ProgressTracker

logger = logging.getLogger(__name__)


class ParallelScanner:
    """Multi-threaded scanner for parallel file analysis."""

    def __init__(
        self,
        vuln_types: List[str],
        max_workers: Optional[int] = None,
        use_cache: bool = True,
        verbose: bool = False,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        plugin_manager=None
    ):
        """
        Initialize parallel scanner.

        Args:
            vuln_types: List of vulnerability types to scan for
            max_workers: Number of worker threads (default: CPU count)
            use_cache: Enable AST caching
            verbose: Enable verbose logging
            progress_callback: Callback for progress updates (completed, total, filename)
            plugin_manager: Optional PluginManager instance
        """
        self.vuln_types = vuln_types
        self.max_workers = max_workers or min(os.cpu_count() or 4, 16)
        self.use_cache = use_cache
        self.verbose = verbose
        self.progress_callback = progress_callback
        self.plugin_manager = plugin_manager

        if use_cache:
            self.cache = ASTCache()
        else:
            self.cache = None

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO if verbose else logging.WARNING)

    def _compute_file_hash(self, filepath: str) -> str:
        """Compute SHA256 hash of file contents."""
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            self.logger.error(f"Error hashing {filepath}: {e}")
            return ""

    def _scan_single_file(
        self,
        filepath: str,
        file_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Scan a single file (worker function).

        Returns:
            Dict with keys: vulnerabilities, warnings, filepath, file_hash,
                          analysis_time, cached
        """
        start_time = time.time()

        try:
            # Compute hash if not provided
            if file_hash is None:
                file_hash = self._compute_file_hash(filepath)

            # Check cache
            cached = False
            if self.cache and file_hash:
                cached_result = self.cache.get(file_hash)
                if cached_result:
                    self.logger.info(f"Cache hit: {filepath}")
                    cached_result['cached'] = True
                    cached_result['filepath'] = filepath
                    cached_result['file_hash'] = file_hash
                    return cached_result

            # Parse and analyze
            with open(filepath, 'rb') as f:
                source_code = f.read()

            tree = PARSER.parse(source_code)
            tracker = TaintTracker(source_code, self.vuln_types, self.verbose)
            result = tracker.analyze(tree, filepath)

            analysis_time = time.time() - start_time

            output = {
                'filepath': filepath,
                'file_hash': file_hash,
                'vulnerabilities': result.get('vulnerabilities', []),
                'warnings': result.get('warnings', []),
                'analysis_time': analysis_time,
                'cached': False,
            }

            # Cache result
            if self.cache and file_hash:
                self.cache.set(file_hash, {
                    'vulnerabilities': output['vulnerabilities'],
                    'warnings': output['warnings'],
                    'analysis_time': analysis_time,
                })

            return output

        except Exception as e:
            self.logger.error(f"Error scanning {filepath}: {e}")
            return {
                'filepath': filepath,
                'file_hash': file_hash or "",
                'vulnerabilities': [],
                'warnings': [],
                'error': str(e),
                'analysis_time': time.time() - start_time,
                'cached': False,
            }

    def scan_files(
        self,
        filepaths: List[str],
        progress_tracker: Optional[ProgressTracker] = None,
        scan_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Scan multiple files in parallel.

        Args:
            filepaths: List of PHP file paths
            progress_tracker: Optional progress tracker
            scan_context: Context dict for plugins

        Returns:
            Dict mapping filepath to scan results
        """
        results = {}
        total_files = len(filepaths)

        self.logger.info(f"Scanning {total_files} files with {self.max_workers} workers")

        # Trigger plugin scan start
        if self.plugin_manager and scan_context:
            self.plugin_manager.trigger_scan_start(scan_context)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(self._scan_single_file, fp): fp
                for fp in filepaths
            }

            # Process completed tasks
            completed = 0
            for future in as_completed(future_to_file):
                filepath = future_to_file[future]
                try:
                    result = future.result()
                    results[filepath] = result

                    # Trigger plugin file scanned
                    if self.plugin_manager:
                        self.plugin_manager.trigger_file_scanned(filepath, result)

                    completed += 1

                    # Update progress
                    if progress_tracker:
                        progress_tracker.update(completed, total_files, filepath)

                    if self.progress_callback:
                        self.progress_callback(completed, total_files, filepath)

                    # Log progress
                    if completed % 10 == 0 or completed == total_files:
                        cache_hits = sum(1 for r in results.values() if r.get('cached'))
                        self.logger.info(
                            f"Progress: {completed}/{total_files} "
                            f"({completed * 100 // total_files}%) - "
                            f"Cache hits: {cache_hits}"
                        )

                except Exception as e:
                    self.logger.error(f"Error processing {filepath}: {e}")
                    results[filepath] = {
                        'filepath': filepath,
                        'vulnerabilities': [],
                        'warnings': [],
                        'error': str(e),
                    }

        # Trigger plugin scan complete
        if self.plugin_manager:
            scan_results = {'files': results, 'statistics': self.get_statistics(results)}
            self.plugin_manager.trigger_scan_complete(scan_results)

        return results

    def scan_directory(
        self,
        directory: str,
        progress_tracker: Optional[ProgressTracker] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Scan all PHP files in a directory recursively.

        Args:
            directory: Root directory path
            progress_tracker: Optional progress tracker

        Returns:
            Dict mapping filepath to scan results
        """
        # Discover PHP files
        path = Path(directory)
        php_files = [str(f) for f in path.rglob('*.php') if f.is_file()]

        if not php_files:
            self.logger.warning(f"No PHP files found in {directory}")
            return {}

        self.logger.info(f"Found {len(php_files)} PHP files in {directory}")

        return self.scan_files(php_files, progress_tracker)

    def get_statistics(self, results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compute statistics from scan results.

        Returns:
            Dict with total_files, total_vulns, total_warnings, cache_hits, etc.
        """
        total_files = len(results)
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results.values())
        total_warnings = sum(len(r.get('warnings', [])) for r in results.values())
        cache_hits = sum(1 for r in results.values() if r.get('cached'))
        total_time = sum(r.get('analysis_time', 0) for r in results.values())
        errors = sum(1 for r in results.values() if 'error' in r)

        # Vulnerability breakdown
        vuln_by_type = {}
        for result in results.values():
            for vuln in result.get('vulnerabilities', []):
                vuln_type = vuln.get('type', 'unknown')
                vuln_by_type[vuln_type] = vuln_by_type.get(vuln_type, 0) + 1

        return {
            'total_files': total_files,
            'total_vulnerabilities': total_vulns,
            'total_warnings': total_warnings,
            'cache_hits': cache_hits,
            'cache_hit_rate': cache_hits / total_files if total_files > 0 else 0,
            'total_analysis_time': total_time,
            'average_time_per_file': total_time / total_files if total_files > 0 else 0,
            'errors': errors,
            'vulnerabilities_by_type': vuln_by_type,
        }
