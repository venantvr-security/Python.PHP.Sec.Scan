# plugins/security_policy.py
"""Plugin for enforcing organizational security policies."""

import sys
from typing import Dict, Any, Optional

from plugins import ScannerPlugin


class SecurityPolicyPlugin(ScannerPlugin):
    """Enforce security policies and fail builds on violations."""

    def __init__(
            self,
            max_critical: int = 0,
            max_high: int = 5,
            max_total: int = 50,
            fail_on_violation: bool = True
    ):
        super().__init__()
        self.name = "Security Policy Enforcer"
        self.max_critical = max_critical
        self.max_high = max_high
        self.max_total = max_total
        self.fail_on_violation = fail_on_violation

        self.counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': 0
        }

    def on_scan_start(self, scan_context: Dict[str, Any]):
        """Print policy thresholds."""
        print(f"\n📋 {self.name}")
        print(f"  Max Critical: {self.max_critical}")
        print(f"  Max High: {self.max_high}")
        print(f"  Max Total: {self.max_total}")
        print(f"  Fail on Violation: {self.fail_on_violation}")

    def on_file_scanned(self, file_path: str, results: Dict[str, Any]):
        """Track vulnerability counts."""
        for vuln in results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'medium')
            self.counts[severity] = self.counts.get(severity, 0) + 1
            self.counts['total'] += 1

    def on_scan_complete(self, scan_results: Dict[str, Any]):
        """Enforce policy and exit if violations found."""
        violations = []

        if self.counts['critical'] > self.max_critical:
            violations.append(
                f"Critical vulnerabilities: {self.counts['critical']} (max: {self.max_critical})"
            )

        if self.counts['high'] > self.max_high:
            violations.append(
                f"High severity vulnerabilities: {self.counts['high']} (max: {self.max_high})"
            )

        if self.counts['total'] > self.max_total:
            violations.append(
                f"Total vulnerabilities: {self.counts['total']} (max: {self.max_total})"
            )

        if violations:
            print("\n" + "=" * 60)
            print("❌ SECURITY POLICY VIOLATIONS")
            print("=" * 60)
            for violation in violations:
                print(f"  • {violation}")
            print("=" * 60)

            if self.fail_on_violation:
                print("\n🛑 Build failed due to security policy violations")
                sys.exit(1)
        else:
            print("\n✅ Security policy: All checks passed")

    def on_vulnerability_found(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Pass through vulnerabilities unchanged."""
        return vulnerability
