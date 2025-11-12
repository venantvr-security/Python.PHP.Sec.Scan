#!/usr/bin/env python3
"""
Performance benchmarking script for PHP Security Scanner.

Tests scanner performance across different configurations:
- With/without caching
- Different worker counts
- Various project sizes
"""

import os
import statistics
import tempfile
import time
from typing import List, Dict

from workers.parallel_scanner import ParallelScanner


def generate_test_files(num_files: int, lines_per_file: int = 50) -> List[str]:
    """Generate test PHP files."""
    tmpdir = tempfile.mkdtemp()
    files = []

    for i in range(num_files):
        filepath = os.path.join(tmpdir, f'test_{i}.php')

        with open(filepath, 'w') as f:
            f.write('<?php\n')
            f.write(f'// Test file {i}\n\n')

            # Generate realistic code
            f.write('function process_data($input) {\n')
            for j in range(lines_per_file // 10):
                f.write(f'    $data_{j} = $_GET["param_{j}"];\n')
                f.write(f'    echo $data_{j};\n')
                f.write(f'    $result_{j} = query("SELECT * FROM users WHERE id = " . $data_{j});\n')
            f.write('    return $result;\n')
            f.write('}\n\n')

            f.write('function safe_process($input) {\n')
            f.write('    $clean = htmlspecialchars($input);\n')
            f.write('    return $clean;\n')
            f.write('}\n')

        files.append(filepath)

    return files, tmpdir


def benchmark_configuration(
        files: List[str],
        workers: int,
        use_cache: bool,
        vuln_types: List[str],
        iterations: int = 3
) -> Dict:
    """Run benchmark for a specific configuration."""
    times = []

    for i in range(iterations):
        scanner = ParallelScanner(
            vuln_types=vuln_types,
            max_workers=workers,
            use_cache=use_cache,
            verbose=False
        )

        start_time = time.time()
        results = scanner.scan_files(files)
        elapsed = time.time() - start_time

        times.append(elapsed)

        stats = scanner.get_statistics(results)

    return {
        'mean_time': statistics.mean(times),
        'median_time': statistics.median(times),
        'min_time': min(times),
        'max_time': max(times),
        'std_dev': statistics.stdev(times) if len(times) > 1 else 0,
        'cache_hit_rate': stats.get('cache_hit_rate', 0),
        'total_vulnerabilities': stats.get('total_vulnerabilities', 0),
    }


def run_benchmarks():
    """Run comprehensive performance benchmarks."""
    print("=" * 70)
    print("PHP SECURITY SCANNER - PERFORMANCE BENCHMARK")
    print("=" * 70)

    # Test configurations
    file_counts = [10, 50, 100]
    worker_counts = [1, 4, 8, 12]
    cache_modes = [False, True]

    vuln_types = ['sql_injection', 'xss', 'rce']

    results = []

    for num_files in file_counts:
        print(f"\nGenerating {num_files} test files...")
        files, tmpdir = generate_test_files(num_files, lines_per_file=50)

        print(f"\nBenchmarking {num_files} files:")
        print("-" * 70)

        for workers in worker_counts:
            for use_cache in cache_modes:
                cache_str = "cached" if use_cache else "no-cache"

                print(f"  Workers: {workers:2d}, Cache: {cache_str:8s} ... ", end='', flush=True)

                try:
                    result = benchmark_configuration(
                        files,
                        workers,
                        use_cache,
                        vuln_types,
                        iterations=3
                    )

                    result.update({
                        'num_files': num_files,
                        'workers': workers,
                        'cache': use_cache,
                    })

                    results.append(result)

                    print(f"{result['median_time']:.2f}s (σ={result['std_dev']:.3f}s)")

                except Exception as e:
                    print(f"ERROR: {e}")

        # Cleanup
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)

    # Print summary
    print("\n" + "=" * 70)
    print("BENCHMARK SUMMARY")
    print("=" * 70)

    print(f"\n{'Files':<8} {'Workers':<8} {'Cache':<10} {'Median':<10} {'StdDev':<10} {'Vulns':<8}")
    print("-" * 70)

    for r in results:
        cache_str = "Yes" if r['cache'] else "No"
        print(f"{r['num_files']:<8} {r['workers']:<8} {cache_str:<10} "
              f"{r['median_time']:<10.3f} {r['std_dev']:<10.3f} {r['total_vulnerabilities']:<8}")

    # Calculate speedups
    print("\n" + "=" * 70)
    print("SPEEDUP ANALYSIS")
    print("=" * 70)

    for num_files in file_counts:
        # Baseline: 1 worker, no cache
        baseline = next((r for r in results if r['num_files'] == num_files
                         and r['workers'] == 1 and not r['cache']), None)

        if not baseline:
            continue

        print(f"\nBaseline ({num_files} files, 1 worker, no cache): {baseline['median_time']:.2f}s")

        # Compare parallel speedup
        for workers in [4, 8, 12]:
            parallel_result = next((r for r in results if r['num_files'] == num_files
                                    and r['workers'] == workers and not r['cache']), None)
            if parallel_result:
                speedup = baseline['median_time'] / parallel_result['median_time']
                print(f"  {workers} workers (no cache):  {parallel_result['median_time']:.2f}s  "
                      f"(speedup: {speedup:.2f}x)")

        # Compare cache speedup
        cached_result = next((r for r in results if r['num_files'] == num_files
                              and r['workers'] == 12 and r['cache']), None)
        if cached_result:
            speedup = baseline['median_time'] / cached_result['median_time']
            print(f"  12 workers + cache:    {cached_result['median_time']:.2f}s  "
                  f"(speedup: {speedup:.2f}x, hit rate: {cached_result['cache_hit_rate']:.1%})")

    # Best configurations
    print("\n" + "=" * 70)
    print("RECOMMENDED CONFIGURATIONS")
    print("=" * 70)

    for num_files in file_counts:
        file_results = [r for r in results if r['num_files'] == num_files]
        best = min(file_results, key=lambda x: x['median_time'])

        cache_str = "with cache" if best['cache'] else "no cache"
        print(f"\n{num_files} files: {best['workers']} workers {cache_str}")
        print(f"  Time: {best['median_time']:.2f}s")
        print(f"  Throughput: {num_files / best['median_time']:.1f} files/sec")


if __name__ == '__main__':
    run_benchmarks()
