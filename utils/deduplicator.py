# utils/deduplicator.py
"""Deduplicate vulnerabilities across scans."""

from typing import List, Dict, Any, Set
import hashlib


class VulnerabilityDeduplicator:
    """Remove duplicate vulnerabilities and track unique issues."""

    @staticmethod
    def get_vulnerability_hash(vuln: Dict[str, Any]) -> str:
        """
        Generate unique hash for vulnerability.

        Based on: type, file, line, sink
        """
        key = f"{vuln['type']}:{vuln.get('file', '')}:{vuln.get('line', 0)}:{vuln.get('sink', '')}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @staticmethod
    def deduplicate(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate vulnerabilities.

        Returns:
            List of unique vulnerabilities
        """
        seen: Set[str] = set()
        unique = []

        for vuln in vulnerabilities:
            vuln_hash = VulnerabilityDeduplicator.get_vulnerability_hash(vuln)

            if vuln_hash not in seen:
                seen.add(vuln_hash)
                vuln['hash'] = vuln_hash
                unique.append(vuln)

        return unique

    @staticmethod
    def compare_scans(
        previous_vulns: List[Dict[str, Any]],
        current_vulns: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Compare two scan results.

        Returns:
            Dict with 'new', 'fixed', 'existing' keys
        """
        prev_hashes = {
            VulnerabilityDeduplicator.get_vulnerability_hash(v): v
            for v in previous_vulns
        }
        curr_hashes = {
            VulnerabilityDeduplicator.get_vulnerability_hash(v): v
            for v in current_vulns
        }

        new_vulns = [
            v for h, v in curr_hashes.items()
            if h not in prev_hashes
        ]

        fixed_vulns = [
            v for h, v in prev_hashes.items()
            if h not in curr_hashes
        ]

        existing_vulns = [
            v for h, v in curr_hashes.items()
            if h in prev_hashes
        ]

        return {
            'new': new_vulns,
            'fixed': fixed_vulns,
            'existing': existing_vulns,
            'summary': {
                'new_count': len(new_vulns),
                'fixed_count': len(fixed_vulns),
                'existing_count': len(existing_vulns),
            }
        }

    @staticmethod
    def group_by_similarity(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group similar vulnerabilities together.

        Groups by type + sink function.
        """
        groups: Dict[str, List[Dict[str, Any]]] = {}

        for vuln in vulnerabilities:
            key = f"{vuln['type']}:{vuln.get('sink', 'unknown')}"

            if key not in groups:
                groups[key] = []

            groups[key].append(vuln)

        return groups


class FalsePositiveFilter:
    """Filter common false positives."""

    # Common false positive patterns
    FALSE_POSITIVE_PATTERNS = {
        'xss': [
            'esc_html', 'esc_attr', 'esc_url',  # WordPress escaping
            'htmlspecialchars', 'htmlentities',  # PHP escaping
        ],
        'sql_injection': [
            '$wpdb->prepare',  # WordPress prepared statements
            'prepare(',  # Generic prepared statements
        ]
    }

    @staticmethod
    def is_likely_false_positive(vuln: Dict[str, Any]) -> bool:
        """
        Check if vulnerability is likely a false positive.

        Basic heuristics:
        - Check if sanitization functions are nearby in trace
        - Check if using prepared statements
        """
        vtype = vuln['type']
        sink = vuln.get('sink', '').lower()
        trace = vuln.get('trace', '').lower()

        patterns = FalsePositiveFilter.FALSE_POSITIVE_PATTERNS.get(vtype, [])

        for pattern in patterns:
            if pattern.lower() in sink or pattern.lower() in trace:
                return True

        return False

    @staticmethod
    def filter_false_positives(
        vulnerabilities: List[Dict[str, Any]],
        aggressive: bool = False
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Filter false positives.

        Args:
            vulnerabilities: List of vulnerabilities
            aggressive: Use aggressive filtering (may miss real issues)

        Returns:
            Tuple of (likely_real, likely_false_positive)
        """
        likely_real = []
        likely_fp = []

        for vuln in vulnerabilities:
            if FalsePositiveFilter.is_likely_false_positive(vuln):
                likely_fp.append(vuln)
            else:
                likely_real.append(vuln)

        return likely_real, likely_fp
