# plugins/metrics_exporter.py
"""Plugin for exporting metrics to monitoring systems (Prometheus/Grafana)."""

import os
import json
from datetime import datetime, timezone
from typing import Dict, Any
from plugins import ScannerPlugin


class MetricsExporterPlugin(ScannerPlugin):
    """Export scan metrics to Prometheus/StatsD/JSON."""

    def __init__(self, export_format='json', output_dir='metrics'):
        super().__init__()
        self.name = "Metrics Exporter Plugin"
        self.export_format = export_format
        self.output_dir = output_dir
        self.metrics = {}

    def on_scan_start(self, scan_context: Dict[str, Any]):
        """Initialize metrics collection."""
        os.makedirs(self.output_dir, exist_ok=True)

        self.metrics = {
            'project': scan_context.get('project', 'unknown'),
            'root_path': scan_context.get('root_path', ''),
            'started_at': datetime.now(timezone.utc).isoformat(),
            'files_processed': 0,
            'vulnerabilities_by_type': {},
            'vulnerabilities_by_severity': {},
            'files_with_vulnerabilities': 0,
        }

    def on_file_scanned(self, file_path: str, results: Dict[str, Any]):
        """Update metrics for each file."""
        self.metrics['files_processed'] += 1

        vulns = results.get('vulnerabilities', [])
        if vulns:
            self.metrics['files_with_vulnerabilities'] += 1

        for vuln in vulns:
            vuln_type = vuln.get('type', 'unknown')
            severity = vuln.get('severity', 'medium')

            self.metrics['vulnerabilities_by_type'][vuln_type] = \
                self.metrics['vulnerabilities_by_type'].get(vuln_type, 0) + 1

            self.metrics['vulnerabilities_by_severity'][severity] = \
                self.metrics['vulnerabilities_by_severity'].get(severity, 0) + 1

    def on_scan_complete(self, scan_results: Dict[str, Any]):
        """Export final metrics."""
        self.metrics['completed_at'] = datetime.now(timezone.utc).isoformat()
        self.metrics['total_vulnerabilities'] = sum(self.metrics['vulnerabilities_by_type'].values())

        stats = scan_results.get('statistics', {})
        self.metrics.update({
            'total_files': stats.get('total_files', 0),
            'cache_hit_rate': stats.get('cache_hit_rate', 0),
            'total_time': stats.get('total_analysis_time', 0),
        })

        # Export based on format
        if self.export_format == 'json':
            self._export_json()
        elif self.export_format == 'prometheus':
            self._export_prometheus()

        print(f"\n📊 Metrics exported to {self.output_dir}/")

    def _export_json(self):
        """Export as JSON."""
        output_file = os.path.join(
            self.output_dir,
            f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        with open(output_file, 'w') as f:
            json.dump(self.metrics, f, indent=2)

    def _export_prometheus(self):
        """Export as Prometheus text format."""
        output_file = os.path.join(self.output_dir, 'metrics.prom')

        lines = [
            '# HELP php_scanner_files_total Total files scanned',
            '# TYPE php_scanner_files_total counter',
            f'php_scanner_files_total {self.metrics["total_files"]}',
            '',
            '# HELP php_scanner_vulnerabilities_total Total vulnerabilities found',
            '# TYPE php_scanner_vulnerabilities_total counter',
            f'php_scanner_vulnerabilities_total {self.metrics["total_vulnerabilities"]}',
            '',
            '# HELP php_scanner_cache_hit_rate Cache hit rate',
            '# TYPE php_scanner_cache_hit_rate gauge',
            f'php_scanner_cache_hit_rate {self.metrics["cache_hit_rate"]:.2f}',
            '',
        ]

        # Vulnerabilities by type
        lines.append('# HELP php_scanner_vulnerabilities_by_type Vulnerabilities by type')
        lines.append('# TYPE php_scanner_vulnerabilities_by_type counter')
        for vuln_type, count in self.metrics['vulnerabilities_by_type'].items():
            lines.append(f'php_scanner_vulnerabilities_by_type{{type="{vuln_type}"}} {count}')

        lines.append('')

        # Vulnerabilities by severity
        lines.append('# HELP php_scanner_vulnerabilities_by_severity Vulnerabilities by severity')
        lines.append('# TYPE php_scanner_vulnerabilities_by_severity counter')
        for severity, count in self.metrics['vulnerabilities_by_severity'].items():
            lines.append(f'php_scanner_vulnerabilities_by_severity{{severity="{severity}"}} {count}')

        with open(output_file, 'w') as f:
            f.write('\n'.join(lines) + '\n')
