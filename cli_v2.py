# cli_v2.py
"""Enhanced CLI with parallel scanning, caching, and database storage."""
import argparse
import json
import sys
from pathlib import Path

from db.connection import get_session, init_db
from db.models import Project, Scan, Vulnerability, Warning, File as FileModel, ScanStatus
from workers.parallel_scanner import ParallelScanner
from workers.progress_tracker import ProgressTracker


def save_to_database(
    project_name: str,
    root_path: str,
    results: dict,
    vuln_types: list,
    statistics: dict
) -> int:
    """
    Save scan results to database.

    Returns:
        scan_id
    """
    with get_session() as session:
        # Get or create project
        project = session.query(Project).filter_by(name=project_name).first()
        if not project:
            project = Project(
                name=project_name,
                root_path=root_path,
            )
            session.add(project)
            session.flush()

        # Create scan
        scan = Scan(
            project_id=project.id,
            vuln_types=vuln_types,
            status=ScanStatus.COMPLETED,
            total_files=statistics['total_files'],
            scanned_files=statistics['total_files'],
            total_vulnerabilities=statistics['total_vulnerabilities'],
            total_warnings=statistics['total_warnings'],
            duration_seconds=statistics['total_analysis_time'],
        )
        session.add(scan)
        session.flush()

        # Save file records
        for filepath, file_result in results.items():
            file_record = FileModel(
                scan_id=scan.id,
                filepath=filepath,
                file_hash=file_result.get('file_hash', ''),
                analyzed=True,
                analysis_duration_ms=file_result.get('analysis_time', 0) * 1000,
                ast_cached=file_result.get('cached', False),
                vulnerabilities_count=len(file_result.get('vulnerabilities', [])),
                warnings_count=len(file_result.get('warnings', [])),
            )
            session.add(file_record)

        # Save vulnerabilities
        for filepath, file_result in results.items():
            for vuln in file_result.get('vulnerabilities', []):
                vuln_record = Vulnerability(
                    scan_id=scan.id,
                    vuln_type=vuln.get('type'),
                    filepath=filepath,
                    line_number=vuln.get('line', 0),
                    sink_function=vuln.get('sink'),
                    tainted_variable=vuln.get('variable'),
                    trace=vuln.get('trace'),
                )
                session.add(vuln_record)

        # Save warnings
        for filepath, file_result in results.items():
            for warn in file_result.get('warnings', []):
                warn_record = Warning(
                    scan_id=scan.id,
                    warning_type=warn.get('type'),
                    filepath=filepath,
                    line_number=warn.get('line', 0),
                    function_name=warn.get('function'),
                    message=warn.get('message'),
                )
                session.add(warn_record)

        session.commit()
        return scan.id


def main():
    parser = argparse.ArgumentParser(
        description='PHP Security Scanner v2 - Multi-threaded with Database Support'
    )

    # Input options
    parser.add_argument('--files', nargs='+', help='PHP files to scan')
    parser.add_argument('--dir', help='Directory to scan recursively')
    parser.add_argument('--project', default='default', help='Project name')

    # Scan configuration
    parser.add_argument(
        '--vuln-types',
        nargs='+',
        default=['sql_injection', 'xss', 'rce', 'file_inclusion', 'command_injection', 'path_traversal'],
        help='Vulnerability types to scan'
    )

    # Performance options
    parser.add_argument('--workers', type=int, help='Number of worker threads')
    parser.add_argument('--no-cache', action='store_true', help='Disable AST caching')

    # Output options
    parser.add_argument('--output', help='Output JSON file')
    parser.add_argument('--no-db', action='store_true', help='Skip database storage')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-progress', action='store_true', help='Disable progress bar')

    # Database management
    parser.add_argument('--init-db', action='store_true', help='Initialize database and exit')

    args = parser.parse_args()

    # Initialize database if requested
    if args.init_db:
        init_db()
        print("Database initialized successfully")
        return 0

    # Validate input
    if not args.files and not args.dir:
        parser.error("Either --files or --dir must be specified")

    # Create scanner
    scanner = ParallelScanner(
        vuln_types=args.vuln_types,
        max_workers=args.workers,
        use_cache=not args.no_cache,
        verbose=args.verbose,
    )

    # Create progress tracker
    progress = None if args.no_progress else ProgressTracker()

    # Scan
    print(f"Starting scan with {scanner.max_workers} workers...")
    print(f"Vulnerability types: {', '.join(args.vuln_types)}")
    print(f"Caching: {'disabled' if args.no_cache else 'enabled'}")

    if args.dir:
        results = scanner.scan_directory(args.dir, progress)
        root_path = args.dir
    else:
        results = scanner.scan_files(args.files, progress)
        root_path = str(Path(args.files[0]).parent)

    # Get statistics
    stats = scanner.get_statistics(results)

    # Print summary
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Total files:          {stats['total_files']}")
    print(f"Total vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"Total warnings:       {stats['total_warnings']}")
    print(f"Cache hit rate:       {stats['cache_hit_rate']:.1%}")
    print(f"Total time:           {stats['total_analysis_time']:.2f}s")
    print(f"Avg time per file:    {stats['average_time_per_file']:.3f}s")
    print(f"Errors:               {stats['errors']}")

    if stats['vulnerabilities_by_type']:
        print("\nVulnerabilities by type:")
        for vuln_type, count in sorted(stats['vulnerabilities_by_type'].items()):
            print(f"  {vuln_type}: {count}")

    # Save to JSON if requested
    if args.output:
        output_data = {
            'scan_config': {
                'vuln_types': args.vuln_types,
                'project': args.project,
                'workers': scanner.max_workers,
            },
            'statistics': stats,
            'results': results,
        }
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\nResults saved to: {args.output}")

    # Save to database
    if not args.no_db:
        try:
            scan_id = save_to_database(
                args.project,
                root_path,
                results,
                args.vuln_types,
                stats
            )
            print(f"Results saved to database (scan_id: {scan_id})")
        except Exception as e:
            print(f"Error saving to database: {e}", file=sys.stderr)

    # Exit code
    return 1 if stats['total_vulnerabilities'] > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
