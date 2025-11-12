# utils/metrics.py
"""Performance and quality metrics utilities."""

from typing import Dict, List, Any
from collections import Counter


class ScanMetrics:
    """Calculate detailed metrics from scan results."""

    @staticmethod
    def calculate_code_quality_score(results: Dict[str, Dict[str, Any]]) -> float:
        """
        Calculate overall code quality score (0-100).

        Higher score = fewer/less severe vulnerabilities.
        """
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results.values())
        total_files = len(results)

        if total_files == 0:
            return 100.0

        # Penalize by vulnerability density
        vuln_density = total_vulns / total_files
        base_score = max(0, 100 - (vuln_density * 10))

        # Additional penalty for severity
        severity_penalty = 0
        for result in results.values():
            for vuln in result.get('vulnerabilities', []):
                severity = vuln.get('severity', 'medium')
                penalty = {'critical': 5, 'high': 3, 'medium': 1, 'low': 0.5}
                severity_penalty += penalty.get(severity, 1)

        score = max(0, base_score - (severity_penalty / total_files))
        return min(100, score)

    @staticmethod
    def vulnerability_distribution(results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate vulnerability distribution statistics."""
        by_type = Counter()
        by_severity = Counter()
        by_file = {}

        for filepath, result in results.items():
            vulns = result.get('vulnerabilities', [])
            by_file[filepath] = len(vulns)

            for vuln in vulns:
                by_type[vuln['type']] += 1
                by_severity[vuln.get('severity', 'medium')] += 1

        # Calculate percentiles
        vuln_counts = list(by_file.values())
        vuln_counts.sort()
        n = len(vuln_counts)

        return {
            'by_type': dict(by_type),
            'by_severity': dict(by_severity),
            'files_with_vulnerabilities': sum(1 for c in vuln_counts if c > 0),
            'hotspot_files': [(f, c) for f, c in sorted(by_file.items(), key=lambda x: -x[1])[:10]],
            'median_vulns_per_file': vuln_counts[n // 2] if n > 0 else 0,
            'p95_vulns_per_file': vuln_counts[int(n * 0.95)] if n > 0 else 0,
        }

    @staticmethod
    def risk_assessment(results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall security risk."""
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results.values())

        critical = sum(
            1 for r in results.values()
            for v in r.get('vulnerabilities', [])
            if v.get('severity') == 'critical'
        )
        high = sum(
            1 for r in results.values()
            for v in r.get('vulnerabilities', [])
            if v.get('severity') == 'high'
        )

        # Calculate risk level
        if critical > 0:
            risk_level = 'CRITICAL'
        elif high > 5:
            risk_level = 'HIGH'
        elif high > 0:
            risk_level = 'MEDIUM'
        elif total_vulns > 10:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'

        return {
            'level': risk_level,
            'critical_count': critical,
            'high_count': high,
            'total_count': total_vulns,
            'recommendation': _get_recommendation(risk_level, critical, high)
        }


def _get_recommendation(risk_level: str, critical: int, high: int) -> str:
    """Get security recommendation based on risk."""
    if risk_level == 'CRITICAL':
        return f"Immediate action required! {critical} critical vulnerabilities must be fixed before deployment."
    elif risk_level == 'HIGH':
        return f"High priority: Address {high} high-severity vulnerabilities as soon as possible."
    elif risk_level == 'MEDIUM':
        return "Review and fix high-severity issues. Consider security audit."
    elif risk_level == 'LOW':
        return "Address remaining vulnerabilities in next sprint."
    else:
        return "Good security posture. Maintain current practices."


class TrendAnalyzer:
    """Analyze trends across multiple scans."""

    def __init__(self):
        self.scan_history: List[Dict[str, Any]] = []

    def add_scan(self, scan_stats: Dict[str, Any]):
        """Add scan to history."""
        self.scan_history.append(scan_stats)

    def get_trend(self) -> Dict[str, Any]:
        """Calculate trend metrics."""
        if len(self.scan_history) < 2:
            return {'trend': 'insufficient_data'}

        recent = self.scan_history[-1]
        previous = self.scan_history[-2]

        vuln_change = recent['total_vulnerabilities'] - previous['total_vulnerabilities']
        vuln_pct_change = (vuln_change / max(previous['total_vulnerabilities'], 1)) * 100

        if vuln_pct_change < -10:
            trend = 'improving'
        elif vuln_pct_change > 10:
            trend = 'degrading'
        else:
            trend = 'stable'

        return {
            'trend': trend,
            'vulnerability_change': vuln_change,
            'percentage_change': vuln_pct_change,
            'scans_analyzed': len(self.scan_history)
        }
