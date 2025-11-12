#!/usr/bin/env python3
"""
Example: Creating a custom plugin for the PHP Security Scanner

This example demonstrates how to create a plugin that:
1. Tracks usage of a specific PHP framework
2. Detects framework-specific security issues
3. Exports custom metrics
"""

import json
from collections import defaultdict
from typing import Dict, Any, Optional

from plugins import ScannerPlugin


class LaravelSecurityPlugin(ScannerPlugin):
    """Custom plugin for Laravel framework security analysis."""

    def __init__(self):
        super().__init__()
        self.name = "Laravel Security Plugin"
        self.version = "1.0.0"

        # Track Laravel-specific items
        self.is_laravel = False
        self.controllers = []
        self.models = []
        self.routes_without_auth = []

        # Laravel security patterns
        self.laravel_patterns = {
            'uses_eloquent_raw': False,
            'uses_db_raw': False,
            'missing_csrf': [],
            'mass_assignment_vulnerable': [],
        }

    def on_scan_start(self, scan_context: Dict[str, Any]):
        """Detect if project is Laravel."""
        import os

        root_path = scan_context.get('root_path', '')

        # Check for Laravel indicators
        laravel_indicators = [
            os.path.join(root_path, 'artisan'),
            os.path.join(root_path, 'composer.json'),
            os.path.join(root_path, 'app', 'Http', 'Kernel.php'),
        ]

        self.is_laravel = any(os.path.exists(f) for f in laravel_indicators)

        if self.is_laravel:
            print(f"✓ Laravel project detected")
            scan_context['is_laravel'] = True
        else:
            print(f"ℹ Not a Laravel project, plugin will be inactive")

    def on_file_scanned(self, file_path: str, results: Dict[str, Any]):
        """Analyze Laravel-specific security issues."""
        if not self.is_laravel:
            return

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Detect Laravel components
            if 'extends Controller' in content or 'class Controller' in content:
                self.controllers.append(file_path)

            if 'extends Model' in content or 'use HasFactory' in content:
                self.models.append(file_path)

            # Check for dangerous raw queries
            if 'DB::raw(' in content or '::raw(' in content:
                self.laravel_patterns['uses_db_raw'] = True
                results.setdefault('laravel_warnings', []).append({
                    'type': 'raw_query',
                    'file': file_path,
                    'message': 'Using DB::raw() - ensure input is sanitized',
                    'severity': 'medium'
                })

            # Check for mass assignment vulnerabilities
            if 'protected $fillable' not in content and 'extends Model' in content:
                self.laravel_patterns['mass_assignment_vulnerable'].append(file_path)
                results.setdefault('laravel_warnings', []).append({
                    'type': 'mass_assignment',
                    'file': file_path,
                    'message': 'Model missing $fillable or $guarded - mass assignment risk',
                    'severity': 'high'
                })

            # Check for routes without middleware (simplified)
            if "Route::" in content and "@csrf" not in content and "->middleware" not in content:
                if "Route::post" in content or "Route::put" in content:
                    self.routes_without_auth.append(file_path)
                    results.setdefault('laravel_warnings', []).append({
                        'type': 'missing_middleware',
                        'file': file_path,
                        'message': 'Route without authentication middleware',
                        'severity': 'medium'
                    })

            # Check for missing CSRF in forms
            if '<form' in content and 'method="POST"' in content.lower():
                if '@csrf' not in content and "csrf_field()" not in content:
                    self.laravel_patterns['missing_csrf'].append(file_path)
                    results.setdefault('laravel_warnings', []).append({
                        'type': 'missing_csrf',
                        'file': file_path,
                        'message': 'POST form without CSRF protection',
                        'severity': 'high'
                    })

        except Exception as e:
            # Silently ignore read errors
            pass

    def on_scan_complete(self, scan_results: Dict[str, Any]):
        """Generate Laravel security report."""
        if not self.is_laravel:
            return

        # Count warnings
        total_laravel_warnings = 0
        warnings_by_type = defaultdict(int)

        for file_result in scan_results.get('files', {}).values():
            for warning in file_result.get('laravel_warnings', []):
                total_laravel_warnings += 1
                warnings_by_type[warning['type']] += 1

        # Add to scan results
        scan_results['laravel'] = {
            'is_laravel': self.is_laravel,
            'controllers_found': len(self.controllers),
            'models_found': len(self.models),
            'total_warnings': total_laravel_warnings,
            'warnings_by_type': dict(warnings_by_type),
            'uses_raw_queries': self.laravel_patterns['uses_db_raw'],
            'missing_csrf_count': len(self.laravel_patterns['missing_csrf']),
            'mass_assignment_vulnerable_count': len(self.laravel_patterns['mass_assignment_vulnerable']),
        }

        # Print summary
        print("\n" + "=" * 60)
        print("LARAVEL SECURITY SUMMARY")
        print("=" * 60)
        print(f"Controllers: {len(self.controllers)}")
        print(f"Models: {len(self.models)}")
        print(f"Laravel Warnings: {total_laravel_warnings}")

        if warnings_by_type:
            print("\nWarnings by type:")
            for warning_type, count in sorted(warnings_by_type.items()):
                print(f"  {warning_type}: {count}")

    def on_vulnerability_found(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process vulnerabilities - add Laravel context."""
        if not self.is_laravel:
            return vulnerability

        # Add Laravel context to SQL injection vulnerabilities
        if vulnerability.get('type') == 'sql_injection':
            vulnerability['laravel_note'] = (
                "Consider using Eloquent ORM or query builder with parameter binding"
            )

        # Add Laravel context to XSS vulnerabilities
        if vulnerability.get('type') == 'xss':
            vulnerability['laravel_note'] = (
                "Use Blade's {{ }} syntax (auto-escapes) instead of {!! !!}"
            )

        return vulnerability


# Example usage
if __name__ == '__main__':
    from plugins import PluginManager
    from workers.parallel_scanner import ParallelScanner
    import sys

    if len(sys.argv) < 2:
        print("Usage: python custom_plugin_example.py /path/to/laravel/project")
        sys.exit(1)

    project_path = sys.argv[1]

    # Initialize plugin manager
    manager = PluginManager()
    manager.register(LaravelSecurityPlugin())

    # Create scanner
    scanner = ParallelScanner(
        vuln_types=['sql_injection', 'xss', 'rce'],
        plugin_manager=manager,
        use_cache=True,
        verbose=True
    )

    # Scan project
    print(f"Scanning Laravel project: {project_path}")

    from pathlib import Path

    php_files = [str(f) for f in Path(project_path).rglob('*.php')]

    scan_context = {'root_path': project_path, 'project': 'laravel-app'}
    results = scanner.scan_files(php_files, scan_context=scan_context)

    # Get statistics
    stats = scanner.get_statistics(results)

    # Export results
    output = {
        'project': 'laravel-app',
        'statistics': stats,
        'laravel_specific': results.get('laravel', {}),
    }

    output_file = 'laravel_security_report.json'
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n✓ Report saved to: {output_file}")
