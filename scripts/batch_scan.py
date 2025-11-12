#!/usr/bin/env python3
"""
Batch scanning script for multiple projects.

Scans multiple projects and generates a consolidated report.
Useful for scanning all projects in an organization.
"""

import argparse
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict

from workers.parallel_scanner import ParallelScanner
from exporters.sarif import SARIFExporter
from suppressions.manager import SuppressionManager
from db.connection import get_session, init_db
from db.models import Project, Scan, Vulnerability, ScanStatus


def find_projects(root_dir: str, indicators: List[str] = None) -> List[Dict]:
    """
    Find PHP projects in a directory tree.

    Args:
        root_dir: Root directory to search
        indicators: Files/dirs that indicate a PHP project

    Returns:
        List of project dicts with path and name
    """
    if indicators is None:
        indicators = ['composer.json', 'index.php', 'wp-config.php', 'artisan']

    projects = []
    root_path = Path(root_dir)

    for item in root_path.iterdir():
        if not item.is_dir():
            continue

        # Check for project indicators
        has_php_files = any(item.rglob('*.php'))

        if has_php_files:
            # Check for specific indicators
            has_indicator = any(
                (item / indicator).exists() for indicator in indicators
            )

            if has_indicator or has_php_files:
                projects.append({
                    'name': item.name,
                    'path': str(item),
                    'type': detect_project_type(item)
                })

    return projects


def detect_project_type(project_path: Path) -> str:
    """Detect project type (WordPress, Laravel, etc.)."""
    if (project_path / 'wp-config.php').exists():
        return 'wordpress'
    elif (project_path / 'artisan').exists():
        return 'laravel'
    elif (project_path / 'composer.json').exists():
        return 'composer'
    else:
        return 'php'


def scan_project(
    project: Dict,
    scanner: ParallelScanner,
    suppression_manager: SuppressionManager
) -> Dict:
    """Scan a single project."""
    print(f"\n{'='*60}")
    print(f"Scanning: {project['name']} ({project['type']})")
    print(f"Path: {project['path']}")
    print(f"{'='*60}")

    # Find PHP files
    php_files = [str(f) for f in Path(project['path']).rglob('*.php')]

    if not php_files:
        print("  ⚠ No PHP files found")
        return {
            'project': project,
            'status': 'empty',
            'files_scanned': 0,
            'vulnerabilities': [],
        }

    print(f"  Found {len(php_files)} PHP files")

    # Scan
    start_time = datetime.now(timezone.utc)
    results = scanner.scan_files(php_files)
    end_time = datetime.now(timezone.utc)

    # Collect vulnerabilities
    all_vulns = []
    for file_result in results.values():
        all_vulns.extend(file_result.get('vulnerabilities', []))

    # Apply suppressions
    active_vulns, suppressed_vulns = suppression_manager.filter_vulnerabilities(all_vulns)

    # Statistics
    stats = scanner.get_statistics(results)

    print(f"  ✓ Files scanned: {len(php_files)}")
    print(f"  ✓ Vulnerabilities: {len(active_vulns)} ({len(suppressed_vulns)} suppressed)")
    print(f"  ✓ Time: {(end_time - start_time).total_seconds():.2f}s")

    return {
        'project': project,
        'status': 'completed',
        'files_scanned': len(php_files),
        'vulnerabilities': active_vulns,
        'suppressed_vulnerabilities': suppressed_vulns,
        'statistics': stats,
        'started_at': start_time.isoformat(),
        'completed_at': end_time.isoformat(),
    }


def save_batch_results(results: List[Dict], output_dir: str):
    """Save batch scan results."""
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Save JSON summary
    summary = {
        'scan_date': datetime.now(timezone.utc).isoformat(),
        'total_projects': len(results),
        'projects': []
    }

    for result in results:
        summary['projects'].append({
            'name': result['project']['name'],
            'type': result['project']['type'],
            'files_scanned': result['files_scanned'],
            'vulnerabilities': len(result['vulnerabilities']),
            'status': result['status'],
        })

    summary_file = os.path.join(output_dir, f'batch_summary_{timestamp}.json')
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\n✓ Summary saved to: {summary_file}")

    # Save detailed results for each project
    for result in results:
        project_name = result['project']['name']
        project_file = os.path.join(output_dir, f'{project_name}_{timestamp}.json')

        with open(project_file, 'w') as f:
            json.dump(result, f, indent=2)

    # Generate SARIF for each project
    exporter = SARIFExporter()
    for result in results:
        if result['vulnerabilities']:
            project_name = result['project']['name']
            sarif_file = os.path.join(output_dir, f'{project_name}_{timestamp}.sarif')

            exporter.export_to_file(result['vulnerabilities'], sarif_file)
            print(f"  ✓ SARIF: {sarif_file}")

    # Generate consolidated HTML report
    generate_html_report(results, output_dir, timestamp)


def generate_html_report(results: List[Dict], output_dir: str, timestamp: str):
    """Generate consolidated HTML report."""
    total_projects = len(results)
    total_files = sum(r['files_scanned'] for r in results)
    total_vulns = sum(len(r['vulnerabilities']) for r in results)

    # Group by severity
    critical = sum(1 for r in results for v in r['vulnerabilities'] if v.get('severity') == 'critical')
    high = sum(1 for r in results for v in r['vulnerabilities'] if v.get('severity') == 'high')
    medium = sum(1 for r in results for v in r['vulnerabilities'] if v.get('severity') == 'medium')
    low = sum(1 for r in results for v in r['vulnerabilities'] if v.get('severity') == 'low')

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Batch Scan Report - {timestamp}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .stats {{ display: flex; gap: 20px; }}
        .stat {{ flex: 1; background: white; padding: 15px; border-radius: 5px; text-align: center; }}
        .stat-value {{ font-size: 32px; font-weight: bold; }}
        .stat-label {{ color: #666; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #333; color: white; }}
        .critical {{ color: #d00; font-weight: bold; }}
        .high {{ color: #f60; font-weight: bold; }}
        .medium {{ color: #f90; }}
        .low {{ color: #999; }}
    </style>
</head>
<body>
    <h1>Batch Security Scan Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

    <div class="summary">
        <h2>Summary</h2>
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{total_projects}</div>
                <div class="stat-label">Projects</div>
            </div>
            <div class="stat">
                <div class="stat-value">{total_files}</div>
                <div class="stat-label">Files Scanned</div>
            </div>
            <div class="stat">
                <div class="stat-value">{total_vulns}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
        </div>

        <h3>By Severity</h3>
        <div class="stats">
            <div class="stat">
                <div class="stat-value critical">{critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat">
                <div class="stat-value high">{high}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat">
                <div class="stat-value medium">{medium}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat">
                <div class="stat-value low">{low}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
    </div>

    <h2>Projects</h2>
    <table>
        <tr>
            <th>Project</th>
            <th>Type</th>
            <th>Files</th>
            <th>Vulnerabilities</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
        </tr>
"""

    for result in results:
        project = result['project']
        vulns = result['vulnerabilities']

        c = sum(1 for v in vulns if v.get('severity') == 'critical')
        h = sum(1 for v in vulns if v.get('severity') == 'high')
        m = sum(1 for v in vulns if v.get('severity') == 'medium')
        l = sum(1 for v in vulns if v.get('severity') == 'low')

        html += f"""
        <tr>
            <td><strong>{project['name']}</strong></td>
            <td>{project['type']}</td>
            <td>{result['files_scanned']}</td>
            <td>{len(vulns)}</td>
            <td class="critical">{c}</td>
            <td class="high">{h}</td>
            <td class="medium">{m}</td>
            <td class="low">{l}</td>
        </tr>
"""

    html += """
    </table>
</body>
</html>
"""

    report_file = os.path.join(output_dir, f'batch_report_{timestamp}.html')
    with open(report_file, 'w') as f:
        f.write(html)

    print(f"\n✓ HTML report: {report_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Batch scan multiple PHP projects'
    )

    parser.add_argument('root_dir', help='Root directory containing projects')
    parser.add_argument('--output', default='batch_results', help='Output directory')
    parser.add_argument('--workers', type=int, default=12, help='Worker threads per project')
    parser.add_argument('--no-cache', action='store_true', help='Disable caching')
    parser.add_argument('--vuln-types', nargs='+',
                       default=['sql_injection', 'xss', 'rce', 'file_inclusion'],
                       help='Vulnerability types')
    parser.add_argument('--save-to-db', action='store_true', help='Save to database')

    args = parser.parse_args()

    # Find projects
    print(f"Searching for PHP projects in: {args.root_dir}")
    projects = find_projects(args.root_dir)

    if not projects:
        print("No projects found!")
        return 1

    print(f"\nFound {len(projects)} projects:")
    for p in projects:
        print(f"  - {p['name']} ({p['type']})")

    # Create scanner
    scanner = ParallelScanner(
        vuln_types=args.vuln_types,
        max_workers=args.workers,
        use_cache=not args.no_cache,
        verbose=False
    )

    # Create suppression manager
    suppression_manager = SuppressionManager()

    # Scan all projects
    results = []
    for project in projects:
        try:
            result = scan_project(project, scanner, suppression_manager)
            results.append(result)
        except Exception as e:
            print(f"  ✗ Error scanning {project['name']}: {e}")
            results.append({
                'project': project,
                'status': 'error',
                'error': str(e),
            })

    # Save results
    save_batch_results(results, args.output)

    # Print final summary
    print(f"\n{'='*60}")
    print("BATCH SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Projects scanned: {len(results)}")
    print(f"Total vulnerabilities: {sum(len(r.get('vulnerabilities', [])) for r in results)}")

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
