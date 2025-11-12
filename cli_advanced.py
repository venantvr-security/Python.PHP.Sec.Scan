#!/usr/bin/env python3
# cli_advanced.py
"""Advanced CLI with all features enabled."""

import argparse
import sys
import os
from pathlib import Path

from cli_v2 import main as cli_v2_main
from exporters.sarif import SARIFExporter
from suppressions.manager import SuppressionManager


def create_parser():
    """Create advanced argument parser."""
    parser = argparse.ArgumentParser(
        description='PHP Security Scanner v2.1 - Advanced CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan with SARIF export
  %(prog)s scan --dir /var/www --project myapp --export-sarif results.sarif

  # Scan with suppressions
  %(prog)s scan --dir /app --suppressions .suppressions.yaml

  # Manage suppressions
  %(prog)s suppress add --file test.php --line 10 --type xss --reason "False positive"

  # Export existing scan to SARIF
  %(prog)s export --scan-id 5 --format sarif --output results.sarif

  # Show statistics
  %(prog)s stats --project myapp
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run security scan')
    scan_parser.add_argument('--dir', required=True, help='Directory to scan')
    scan_parser.add_argument('--project', required=True, help='Project name')
    scan_parser.add_argument('--workers', type=int, default=12, help='Number of workers')
    scan_parser.add_argument('--vuln-types', nargs='+', help='Vulnerability types to scan')
    scan_parser.add_argument('--export-sarif', help='Export results to SARIF file')
    scan_parser.add_argument('--export-json', help='Export results to JSON file')
    scan_parser.add_argument('--suppressions', help='Suppression file')
    scan_parser.add_argument('--no-cache', action='store_true', help='Disable cache')
    scan_parser.add_argument('--no-db', action='store_true', help='Skip database storage')
    scan_parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'],
                           help='Minimum severity to report')
    scan_parser.add_argument('--exclude', nargs='+', help='Patterns to exclude')
    scan_parser.add_argument('--include', nargs='+', help='Patterns to include')
    scan_parser.add_argument('--max-files', type=int, help='Maximum files to scan')
    scan_parser.add_argument('--timeout', type=int, default=300, help='Scan timeout in seconds')

    # Suppress command
    suppress_parser = subparsers.add_parser('suppress', help='Manage suppressions')
    suppress_subparsers = suppress_parser.add_subparsers(dest='suppress_action')

    add_suppress = suppress_subparsers.add_parser('add', help='Add suppression')
    add_suppress.add_argument('--file', required=True, help='File path')
    add_suppress.add_argument('--line', type=int, required=True, help='Line number')
    add_suppress.add_argument('--type', required=True, help='Vulnerability type')
    add_suppress.add_argument('--reason', required=True, help='Suppression reason')
    add_suppress.add_argument('--author', default='cli', help='Author name')

    list_suppress = suppress_subparsers.add_parser('list', help='List suppressions')
    list_suppress.add_argument('--file', help='Suppression file')

    # Export command
    export_parser = subparsers.add_parser('export', help='Export scan results')
    export_parser.add_argument('--scan-id', type=int, required=True, help='Scan ID')
    export_parser.add_argument('--format', choices=['sarif', 'json', 'html', 'csv'],
                              default='sarif', help='Export format')
    export_parser.add_argument('--output', required=True, help='Output file')

    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show statistics')
    stats_parser.add_argument('--project', help='Project name')
    stats_parser.add_argument('--scan-id', type=int, help='Specific scan ID')

    # Cache command
    cache_parser = subparsers.add_parser('cache', help='Manage cache')
    cache_subparsers = cache_parser.add_subparsers(dest='cache_action')
    cache_subparsers.add_parser('clear', help='Clear cache')
    cache_subparsers.add_parser('stats', help='Show cache statistics')

    return parser


def handle_scan(args):
    """Handle scan command."""
    # Build arguments for cli_v2
    sys.argv = ['cli_v2.py', '--dir', args.dir, '--project', args.project]

    if args.workers:
        sys.argv.extend(['--workers', str(args.workers)])
    if args.vuln_types:
        sys.argv.extend(['--vuln-types'] + args.vuln_types)
    if args.no_cache:
        sys.argv.append('--no-cache')
    if args.no_db:
        sys.argv.append('--no-db')
    if args.export_json:
        sys.argv.extend(['--output', args.export_json])

    # Run scan
    cli_v2_main()

    # Handle SARIF export if requested
    if args.export_sarif and not args.no_db:
        from db.connection import get_session
        from db.models import Scan, Vulnerability

        with get_session() as session:
            # Get latest scan for project
            from db.models import Project
            project = session.query(Project).filter_by(name=args.project).first()
            if project:
                scan = session.query(Scan).filter_by(project_id=project.id)\
                    .order_by(Scan.id.desc()).first()
                if scan:
                    vulns = session.query(Vulnerability).filter_by(scan_id=scan.id).all()
                    vuln_dicts = [
                        {
                            'type': v.vuln_type,
                            'file': v.file_path,
                            'line': v.line_number,
                            'column': v.column_number,
                            'severity': v.severity,
                            'sink': v.sink_function
                        }
                        for v in vulns
                    ]

                    exporter = SARIFExporter()
                    exporter.export_to_file(vuln_dicts, args.export_sarif, args.dir)
                    print(f"\n✓ SARIF exported to: {args.export_sarif}")


def handle_suppress(args):
    """Handle suppress command."""
    manager = SuppressionManager()

    if args.suppress_action == 'add':
        vuln = {
            'type': args.type,
            'file': args.file,
            'line': args.line
        }
        manager.add_suppression(vuln, args.reason, args.author)
        print(f"✓ Suppression added for {args.file}:{args.line}")

    elif args.suppress_action == 'list':
        if args.file:
            manager = SuppressionManager(args.file)

        print(f"\nSuppressions ({len(manager.suppressions)}):")
        for i, s in enumerate(manager.suppressions, 1):
            print(f"  {i}. {s.get('file', 'N/A')}:{s.get('line', 'N/A')} "
                  f"[{s.get('type', 'N/A')}] - {s.get('reason', 'N/A')}")


def handle_export(args):
    """Handle export command."""
    from db.connection import get_session
    from db.models import Scan, Vulnerability

    with get_session() as session:
        scan = session.query(Scan).filter_by(id=args.scan_id).first()
        if not scan:
            print(f"Error: Scan {args.scan_id} not found")
            return

        vulns = session.query(Vulnerability).filter_by(scan_id=args.scan_id).all()
        vuln_dicts = [
            {
                'type': v.vuln_type,
                'file': v.file_path,
                'line': v.line_number,
                'column': v.column_number,
                'severity': v.severity,
                'sink': v.sink_function
            }
            for v in vulns
        ]

        if args.format == 'sarif':
            exporter = SARIFExporter()
            exporter.export_to_file(vuln_dicts, args.output)
            print(f"✓ Exported {len(vuln_dicts)} vulnerabilities to {args.output}")


def handle_stats(args):
    """Handle stats command."""
    from db.connection import get_session
    from db.models import Project, Scan, Vulnerability

    with get_session() as session:
        if args.project:
            project = session.query(Project).filter_by(name=args.project).first()
            if not project:
                print(f"Error: Project '{args.project}' not found")
                return

            print(f"\n📊 Statistics for {project.name}")
            print(f"   Root path: {project.root_path}")
            print(f"   Total scans: {len(project.scans)}")

            total_vulns = sum(scan.total_vulnerabilities for scan in project.scans)
            print(f"   Total vulnerabilities: {total_vulns}")


def handle_cache(args):
    """Handle cache command."""
    from cache.ast_cache import ASTCache

    cache = ASTCache()

    if args.cache_action == 'clear':
        cache.clear()
        print("✓ Cache cleared")

    elif args.cache_action == 'stats':
        stats = cache.get_stats()
        print(f"\n📊 Cache Statistics:")
        print(f"   Total keys: {stats.get('size', 0)}")
        print(f"   Cache directory: {stats.get('directory', 'N/A')}")


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == 'scan':
            handle_scan(args)
        elif args.command == 'suppress':
            handle_suppress(args)
        elif args.command == 'export':
            handle_export(args)
        elif args.command == 'stats':
            handle_stats(args)
        elif args.command == 'cache':
            handle_cache(args)
    except KeyboardInterrupt:
        print("\n\n⚠ Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if os.getenv('DEBUG'):
            raise
        sys.exit(1)


if __name__ == '__main__':
    main()
