# plugins/custom_rules.py
"""Example plugin for adding custom security rules."""

from typing import Dict, Any, Optional
from plugins import ScannerPlugin


class CustomRulesPlugin(ScannerPlugin):
    """Plugin for adding custom organization-specific rules."""

    def __init__(self):
        super().__init__()
        self.name = "Custom Rules Plugin"
        self.version = "1.0.0"

        # Custom patterns to detect
        self.dangerous_functions = {
            'mysql_query', 'mysql_fetch_array', 'mysql_connect',  # Deprecated MySQL
            'create_function',  # Deprecated in PHP 7.2
            'assert',  # Can be used for code execution
            'preg_replace',  # /e modifier vulnerability
        }

        self.insecure_patterns = {
            'extract': 'Variable extraction without second parameter',
            'parse_str': 'Parse string without second parameter',
            '$$': 'Variable variables can be dangerous',
        }

    def on_scan_start(self, scan_context: Dict[str, Any]):
        """Initialize custom rule tracking."""
        print(f"✓ {self.name} loaded")
        print(f"  Tracking {len(self.dangerous_functions)} dangerous functions")
        print(f"  Tracking {len(self.insecure_patterns)} insecure patterns")

    def on_file_scanned(self, file_path: str, results: Dict[str, Any]):
        """Check for custom rule violations."""
        # This is a simplified example - in production you'd analyze the AST
        try:
            with open(file_path, 'r') as f:
                content = f.read()

            # Check for dangerous functions
            for func in self.dangerous_functions:
                if func in content:
                    results.setdefault('custom_warnings', []).append({
                        'type': 'deprecated_function',
                        'function': func,
                        'file': file_path,
                        'severity': 'medium',
                        'message': f'Deprecated or dangerous function: {func}'
                    })

            # Check for insecure patterns
            for pattern, description in self.insecure_patterns.items():
                if pattern in content:
                    results.setdefault('custom_warnings', []).append({
                        'type': 'insecure_pattern',
                        'pattern': pattern,
                        'file': file_path,
                        'severity': 'low',
                        'message': description
                    })

        except Exception:
            pass

    def on_scan_complete(self, scan_results: Dict[str, Any]):
        """Summarize custom rule findings."""
        total_warnings = 0
        for file_result in scan_results.get('files', {}).values():
            total_warnings += len(file_result.get('custom_warnings', []))

        if total_warnings > 0:
            print(f"\n⚠ Custom Rules: {total_warnings} warnings found")

    def on_vulnerability_found(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process vulnerability - can modify severity or add context."""
        # Example: Increase severity if certain functions are involved
        if vulnerability.get('sink') in self.dangerous_functions:
            if vulnerability.get('severity') == 'medium':
                vulnerability['severity'] = 'high'
                vulnerability['reason'] = 'Involves deprecated function'

        return vulnerability
