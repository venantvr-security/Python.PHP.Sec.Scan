# utils/reporting.py
"""Advanced reporting utilities."""

from typing import Dict, List, Any
import json


class ReportGenerator:
    """Generate various report formats."""

    @staticmethod
    def generate_executive_summary(
        scan_stats: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]]
    ) -> str:
        """Generate executive summary for management."""
        from utils.metrics import ScanMetrics

        metrics = ScanMetrics()
        results_mock = {f'file{i}': {'vulnerabilities': []} for i in range(scan_stats.get('total_files', 1))}

        # Distribute vulnerabilities
        for i, vuln in enumerate(vulnerabilities):
            file_idx = i % len(results_mock)
            results_mock[f'file{file_idx}']['vulnerabilities'].append(vuln)

        quality_score = metrics.calculate_code_quality_score(results_mock)
        risk = metrics.risk_assessment(results_mock)

        summary = f"""
╔═══════════════════════════════════════════════════════════════╗
║                  SECURITY SCAN EXECUTIVE SUMMARY              ║
╚═══════════════════════════════════════════════════════════════╝

📊 OVERVIEW
  • Files Scanned:        {scan_stats.get('total_files', 0)}
  • Vulnerabilities:      {scan_stats.get('total_vulnerabilities', 0)}
  • Code Quality Score:   {quality_score:.1f}/100
  • Risk Level:           {risk['level']}

🎯 KEY FINDINGS
  • Critical Issues:      {risk['critical_count']}
  • High Severity:        {risk['high_count']}
  • Scan Time:            {scan_stats.get('total_analysis_time', 0):.2f}s
  • Cache Efficiency:     {scan_stats.get('cache_hit_rate', 0):.1%}

💡 RECOMMENDATION
  {risk['recommendation']}

"""
        return summary

    @staticmethod
    def generate_json_report(
        scan_stats: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        output_file: str = None
    ) -> str:
        """Generate comprehensive JSON report."""
        from utils.metrics import ScanMetrics

        report = {
            'version': '2.3.0',
            'statistics': scan_stats,
            'vulnerabilities': vulnerabilities,
            'summary': {
                'total': len(vulnerabilities),
                'by_severity': {},
                'by_type': {}
            }
        }

        # Calculate summaries
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'medium')
            vtype = vuln['type']
            report['summary']['by_severity'][severity] = report['summary']['by_severity'].get(severity, 0) + 1
            report['summary']['by_type'][vtype] = report['summary']['by_type'].get(vtype, 0) + 1

        json_str = json.dumps(report, indent=2)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_str)

        return json_str

    @staticmethod
    def generate_markdown_report(
        scan_stats: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]]
    ) -> str:
        """Generate Markdown report for documentation."""
        from collections import Counter

        by_type = Counter(v['type'] for v in vulnerabilities)
        by_severity = Counter(v.get('severity', 'medium') for v in vulnerabilities)

        md = f"""# Security Scan Report

## Summary

- **Files Scanned:** {scan_stats.get('total_files', 0)}
- **Total Vulnerabilities:** {len(vulnerabilities)}
- **Scan Time:** {scan_stats.get('total_analysis_time', 0):.2f}s
- **Cache Hit Rate:** {scan_stats.get('cache_hit_rate', 0):.1%}

## Vulnerabilities by Severity

| Severity | Count |
|----------|-------|
| Critical | {by_severity.get('critical', 0)} |
| High     | {by_severity.get('high', 0)} |
| Medium   | {by_severity.get('medium', 0)} |
| Low      | {by_severity.get('low', 0)} |

## Vulnerabilities by Type

| Type | Count |
|------|-------|
"""

        for vtype, count in sorted(by_type.items(), key=lambda x: -x[1]):
            md += f"| {vtype} | {count} |\n"

        md += "\n## Detailed Findings\n\n"

        for i, vuln in enumerate(vulnerabilities[:20], 1):
            md += f"""
### {i}. {vuln['type']} - {vuln.get('severity', 'medium').upper()}

- **File:** `{vuln.get('file', 'N/A')}`
- **Line:** {vuln.get('line', 0)}
- **Sink:** `{vuln.get('sink', 'N/A')}`
- **Variable:** `{vuln.get('variable', 'N/A')}`

"""

        if len(vulnerabilities) > 20:
            md += f"\n*... and {len(vulnerabilities) - 20} more*\n"

        return md


class ConsoleFormatter:
    """Format output for console with colors."""

    COLORS = {
        'critical': '\033[91m',
        'high': '\033[93m',
        'medium': '\033[33m',
        'low': '\033[36m',
        'reset': '\033[0m',
        'bold': '\033[1m',
        'green': '\033[92m',
    }

    @staticmethod
    def format_vulnerability(vuln: Dict[str, Any]) -> str:
        """Format single vulnerability for console."""
        severity = vuln.get('severity', 'medium')
        color = ConsoleFormatter.COLORS.get(severity, '')
        reset = ConsoleFormatter.COLORS['reset']

        return (
            f"{color}[{severity.upper()}]{reset} "
            f"{vuln['type']} in {vuln.get('file', 'N/A')}:{vuln.get('line', 0)}"
        )

    @staticmethod
    def format_summary(stats: Dict[str, Any]) -> str:
        """Format scan summary for console."""
        c = ConsoleFormatter.COLORS

        return f"""
{c['bold']}Scan Complete{c['reset']}
  Files:    {stats.get('total_files', 0)}
  Vulns:    {stats.get('total_vulnerabilities', 0)}
  Time:     {stats.get('total_analysis_time', 0):.2f}s
  Cache:    {c['green']}{stats.get('cache_hit_rate', 0):.1%}{c['reset']}
"""
