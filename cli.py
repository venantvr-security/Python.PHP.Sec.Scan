#!/usr/bin/env python3
"""
PHP Security Scanner - Unified CLI
Consolidated command-line interface with all features.
"""
import argparse
import json
import sys
from pathlib import Path

from db.connection import get_session, init_db
from db.models import Project, Scan, Vulnerability, ScanStatus
from exporters.html_report import HTMLReportGenerator
from exporters.sarif import SARIFExporter
from plugins import PluginManager, WordPressPlugin, PerformancePlugin
from suppressions.manager import SuppressionManager
from workers.parallel_scanner import ParallelScanner
from workers.progress_tracker import ProgressTracker


def cmd_scan(args):
    """Run security scan with optimizations."""
    if not args.files and not args.dir:
        print("Error: Either --files or --dir must be specified", file=sys.stderr)
        return 1

    plugin_manager = None
    if args.enable_plugins:
        plugin_manager = PluginManager()
        plugin_manager.register(WordPressPlugin())
        plugin_manager.register(PerformancePlugin())
        if args.load_plugins_from:
            plugin_manager.load_from_directory(args.load_plugins_from)

    scanner = ParallelScanner(
        vuln_types=args.vuln_types,
        max_workers=args.workers,
        use_cache=not args.no_cache,
        verbose=args.verbose,
        plugin_manager=plugin_manager,
    )

    progress = None if args.no_progress else ProgressTracker()

    print(f"Scan: {scanner.max_workers} workers")
    print(f"Types: {', '.join(args.vuln_types)}")
    print(f"Cache: {'OFF' if args.no_cache else 'ON'}")
    if args.enable_plugins:
        print(f"Plugins: ON")

    if args.dir:
        root_path = args.dir
        scan_context = {'root_path': root_path, 'project': args.project}
        files = [str(f) for f in Path(root_path).rglob('*.php')]
        results = scanner.scan_files(files, progress, scan_context)
    else:
        root_path = str(Path(args.files[0]).parent)
        scan_context = {'root_path': root_path, 'project': args.project}
        results = scanner.scan_files(args.files, progress, scan_context)

    stats = scanner.get_statistics(results)

    print("\n" + "=" * 50)
    print("SCAN SUMMARY")
    print("=" * 50)
    print(f"Files:         {stats['total_files']}")
    print(f"Vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"Warnings:      {stats['total_warnings']}")
    print(f"Cache hits:    {stats['cache_hits']}/{stats['total_files']} ({stats['cache_hit_rate']:.1%})")
    print(f"Time:          {stats['total_analysis_time']:.2f}s (avg: {stats['average_time_per_file']:.3f}s/file)")

    if stats['vulnerabilities_by_type']:
        print("\nBy type:")
        for vuln_type, count in sorted(stats['vulnerabilities_by_type'].items(), key=lambda x: -x[1]):
            print(f"  {vuln_type}: {count}")

    if args.output:
        output_data = {
            'scan_config': {'vuln_types': args.vuln_types, 'project': args.project},
            'statistics': stats,
            'results': results,
        }
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\n✓ Results saved to: {args.output}")

    if not args.no_db:
        try:
            with get_session() as session:
                project = session.query(Project).filter_by(name=args.project).first()
                if not project:
                    project = Project(name=args.project, root_path=root_path)
                    session.add(project)
                    session.flush()

                scan = Scan(
                    project_id=project.id,
                    vuln_types=args.vuln_types,
                    status=ScanStatus.COMPLETED,
                    total_files=stats['total_files'],
                    scanned_files=stats['total_files'],
                    total_vulnerabilities=stats['total_vulnerabilities'],
                    duration_seconds=stats['total_analysis_time'],
                )
                session.add(scan)
                session.flush()

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

                session.commit()
                print(f"✓ Results saved to database (scan_id: {scan.id})")
        except Exception as e:
            print(f"Error saving to database: {e}", file=sys.stderr)

    if args.export_sarif:
        all_vulns = []
        for file_result in results.values():
            all_vulns.extend(file_result.get('vulnerabilities', []))
        exporter = SARIFExporter()
        exporter.export_to_file(all_vulns, args.export_sarif)
        print(f"✓ SARIF export: {args.export_sarif}")

    return 1 if stats['total_vulnerabilities'] > 0 else 0


def cmd_export(args):
    """Export scan results."""
    with get_session() as session:
        scan = session.query(Scan).filter_by(id=int(args.scan_id) if args.scan_id != 'latest' else None).first() if args.scan_id != 'latest' else session.query(
            Scan).order_by(Scan.created_at.desc()).first()

        if not scan:
            print("Error: Scan not found", file=sys.stderr)
            return 1

        vulns = session.query(Vulnerability).filter_by(scan_id=scan.id).all()
        vuln_dicts = [{'type': v.vuln_type, 'file': v.filepath, 'line': v.line_number, 'severity': v.severity.value if hasattr(v.severity, 'value') else 'medium',
                       'sink': v.sink_function, 'variable': v.tainted_variable, 'trace': v.trace} for v in vulns]

        if args.format == 'sarif':
            SARIFExporter().export_to_file(vuln_dicts, args.output)
        elif args.format == 'json':
            with open(args.output, 'w') as f:
                json.dump({'scan_id': scan.id, 'project': scan.project.name, 'vulnerabilities': vuln_dicts}, f, indent=2)
        elif args.format == 'html':
            with open(args.output, 'w') as f:
                f.write(HTMLReportGenerator().generate(vuln_dicts, scan.project.name))

        print(f"✓ {args.format.upper()} exported to {args.output}")
    return 0


def cmd_suppress(args):
    """Manage suppressions."""
    manager = SuppressionManager()
    if args.suppress_cmd == 'list':
        for i, s in enumerate(manager.list_suppressions(), 1):
            print(f"{i}. {s['file']}:{s['line']} ({s['type']}) - {s['reason']}")
    elif args.suppress_cmd == 'add':
        manager.add_suppression({'file': args.file, 'line': args.line, 'type': args.type}, args.reason, args.author or 'cli')
        print(f"✓ Suppression added")
    elif args.suppress_cmd == 'remove':
        manager.remove_suppression(args.id)
        print(f"✓ Suppression removed")
    return 0


def cmd_stats(args):
    """Show statistics."""
    with get_session() as session:
        if args.project:
            project = session.query(Project).filter_by(name=args.project).first()
            if not project:
                print(f"Error: Project not found", file=sys.stderr)
                return 1
            scans = session.query(Scan).filter_by(project_id=project.id).all()
            print(f"Project: {project.name} - {len(scans)} scans")
            for scan in scans[-10:]:
                print(f"  #{scan.id} - {scan.created_at.strftime('%Y-%m-%d %H:%M')} - {scan.total_vulnerabilities} vulns")
        elif args.scan_id:
            scan = session.query(Scan).filter_by(id=args.scan_id).first()
            if scan:
                print(f"Scan #{scan.id} - {scan.project.name}")
                print(f"Files: {scan.total_files}, Vulns: {scan.total_vulnerabilities}, Time: {scan.duration_seconds:.2f}s")
    return 0


def cmd_cache(args):
    """Manage cache."""
    from cache.ast_cache import ASTCache

    cache = ASTCache()
    if args.cache_cmd == 'clear':
        cache.cache.clear()
        print("✓ Cache cleared")
    elif args.cache_cmd == 'stats':
        print(f"Cache: {len(cache.cache)} entries")
    return 0


def cmd_projects(args):
    """Manage projects."""
    with get_session() as session:
        if args.project_cmd == 'list':
            for p in session.query(Project).all():
                print(f"{p.name} - {p.root_path} ({len(p.scans)} scans)")
        elif args.project_cmd == 'info':
            project = session.query(Project).filter_by(name=args.name).first()
            if project:
                print(f"Project: {project.name}\nPath: {project.root_path}\nScans: {len(project.scans)}")
    return 0


def main():
    parser = argparse.ArgumentParser(description='PHP Security Scanner',
                                     epilog='Examples:\n  %(prog)s scan --dir /app\n  %(prog)s export --scan-id 1 --format sarif -o report.sarif',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest='command')

    parser.add_argument('--init-db', action='store_true', help='Initialize database')

    # Scan
    p_scan = subparsers.add_parser('scan')
    p_scan.add_argument('--files', nargs='+')
    p_scan.add_argument('--dir')
    p_scan.add_argument('--project', default='default')
    p_scan.add_argument('--vuln-types', nargs='+', default=['sql_injection', 'xss', 'rce', 'file_inclusion', 'command_injection', 'path_traversal'])
    p_scan.add_argument('--workers', type=int)
    p_scan.add_argument('--no-cache', action='store_true')
    p_scan.add_argument('--output')
    p_scan.add_argument('--no-db', action='store_true')
    p_scan.add_argument('--verbose', action='store_true')
    p_scan.add_argument('--no-progress', action='store_true')
    p_scan.add_argument('--enable-plugins', action='store_true')
    p_scan.add_argument('--load-plugins-from')
    p_scan.add_argument('--export-sarif')
    p_scan.set_defaults(func=cmd_scan)

    # Export
    p_export = subparsers.add_parser('export')
    p_export.add_argument('--scan-id', required=True)
    p_export.add_argument('--format', required=True, choices=['sarif', 'json', 'html'])
    p_export.add_argument('--output', '-o', required=True)
    p_export.set_defaults(func=cmd_export)

    # Suppress
    p_suppress = subparsers.add_parser('suppress')
    s_sub = p_suppress.add_subparsers(dest='suppress_cmd')
    s_list = s_sub.add_parser('list')
    s_list.set_defaults(func=cmd_suppress)
    s_add = s_sub.add_parser('add')
    s_add.add_argument('--file', required=True)
    s_add.add_argument('--line', type=int, required=True)
    s_add.add_argument('--type', required=True)
    s_add.add_argument('--reason', required=True)
    s_add.add_argument('--author')
    s_add.set_defaults(func=cmd_suppress)
    s_rm = s_sub.add_parser('remove')
    s_rm.add_argument('--id', type=int, required=True)
    s_rm.set_defaults(func=cmd_suppress)

    # Stats
    p_stats = subparsers.add_parser('stats')
    p_stats.add_argument('--project')
    p_stats.add_argument('--scan-id', type=int)
    p_stats.set_defaults(func=cmd_stats)

    # Cache
    p_cache = subparsers.add_parser('cache')
    c_sub = p_cache.add_subparsers(dest='cache_cmd')
    c_clear = c_sub.add_parser('clear')
    c_clear.set_defaults(func=cmd_cache)
    c_stats = c_sub.add_parser('stats')
    c_stats.set_defaults(func=cmd_cache)

    # Projects
    p_proj = subparsers.add_parser('projects')
    pr_sub = p_proj.add_subparsers(dest='project_cmd')
    pr_list = pr_sub.add_parser('list')
    pr_list.set_defaults(func=cmd_projects)
    pr_info = pr_sub.add_parser('info')
    pr_info.add_argument('--name', required=True)
    pr_info.set_defaults(func=cmd_projects)

    args = parser.parse_args()

    if args.init_db:
        init_db()
        print("✓ Database initialized")
        return 0

    if hasattr(args, 'func'):
        return args.func(args)
    parser.print_help()
    return 1


if __name__ == '__main__':
    sys.exit(main())
