# exporters/sarif.py
"""SARIF (Static Analysis Results Interchange Format) exporter."""

import hashlib
import json
from datetime import datetime, timezone
from typing import List, Dict


class SARIFExporter:
    """Export vulnerabilities in SARIF 2.1.0 format."""

    def __init__(self, tool_name: str = "PHP-Security-Scanner", tool_version: str = "2.4.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version
        self._rule_cache: Dict[str, Dict] = {}

    def export(self, vulnerabilities: List[Dict], project_root: str = ".") -> Dict:
        """Convert vulnerabilities to SARIF format."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/your-org/php-security-scanner",
                            "rules": self._generate_rules(vulnerabilities)
                        }
                    },
                    "results": self._convert_vulnerabilities(vulnerabilities, project_root),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                        }
                    ]
                }
            ]
        }
        return sarif

    def export_to_file(self, vulnerabilities: List[Dict], output_file: str, project_root: str = "."):
        """Export vulnerabilities to SARIF file."""
        sarif = self.export(vulnerabilities, project_root)
        with open(output_file, 'w') as f:
            json.dump(sarif, f, indent=2)

    def _generate_rules(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate SARIF rules from vulnerability types with caching."""
        vuln_types = {}
        for vuln in vulnerabilities:
            vtype = vuln['type']
            if vtype not in vuln_types:
                if vtype in self._rule_cache:
                    vuln_types[vtype] = self._rule_cache[vtype]
                else:
                    rule = {
                        "id": vtype,
                        "name": vtype.replace('_', ' ').title(),
                        "shortDescription": {"text": self._get_description(vtype)},
                        "fullDescription": {"text": self._get_full_description(vtype)},
                        "help": {"text": self._get_help(vtype)},
                        "defaultConfiguration": {"level": self._get_level(vuln.get('severity', 'medium'))},
                        "properties": {"tags": self._get_tags(vtype), "precision": "high"}
                    }
                    self._rule_cache[vtype] = rule
                    vuln_types[vtype] = rule

        return list(vuln_types.values())

    def _convert_vulnerabilities(self, vulnerabilities: List[Dict], project_root: str) -> List[Dict]:
        """Convert vulnerabilities to SARIF results."""
        results = []
        for vuln in vulnerabilities:
            result = {
                "ruleId": vuln['type'],
                "level": self._get_level(vuln.get('severity', 'medium')),
                "message": {
                    "text": self._get_message(vuln)
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": vuln['file'].replace(project_root + '/', ''),
                                "uriBaseId": "SRCROOT"
                            },
                            "region": {
                                "startLine": vuln['line'],
                                "startColumn": vuln.get('column', 1)
                            }
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": self._hash_location(vuln)
                }
            }

            # Add code flow for inter-procedural vulnerabilities
            if vuln.get('interprocedural') and 'call_chain' in vuln:
                result['codeFlows'] = [self._create_code_flow(vuln['call_chain'])]

            # Add fix suggestions
            if 'fix_suggestion' in vuln:
                result['fixes'] = [self._create_fix(vuln)]

            results.append(result)

        return results

    def _create_code_flow(self, call_chain: List[Dict]) -> Dict:
        """Create SARIF code flow from call chain."""
        thread_flows = []
        for i, call in enumerate(call_chain):
            thread_flows.append({
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": call['file']
                        },
                        "region": {
                            "startLine": call['line']
                        }
                    },
                    "message": {
                        "text": f"Call to {call.get('function', 'unknown')}"
                    }
                },
                "nestingLevel": i
            })

        return {
            "threadFlows": [
                {
                    "locations": thread_flows
                }
            ]
        }

    def _create_fix(self, vuln: Dict) -> Dict:
        """Create SARIF fix suggestion."""
        return {
            "description": {
                "text": vuln.get('fix_suggestion', 'Apply security fix')
            },
            "artifactChanges": [
                {
                    "artifactLocation": {
                        "uri": vuln['file']
                    },
                    "replacements": [
                        {
                            "deletedRegion": {
                                "startLine": vuln['line'],
                                "startColumn": vuln.get('column', 1)
                            }
                        }
                    ]
                }
            ]
        }

    def _hash_location(self, vuln: Dict) -> str:
        """Generate hash for vulnerability location."""
        content = f"{vuln['file']}:{vuln['line']}:{vuln['type']}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _get_level(self, severity: str) -> str:
        """Map severity to SARIF level."""
        mapping = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note'
        }
        return mapping.get(severity.lower(), 'warning')

    def _get_description(self, vuln_type: str) -> str:
        """Get short description for vulnerability type."""
        descriptions = {
            'sql_injection': 'SQL Injection vulnerability',
            'xss': 'Cross-Site Scripting (XSS) vulnerability',
            'rce': 'Remote Code Execution vulnerability',
            'file_inclusion': 'File Inclusion vulnerability',
            'command_injection': 'Command Injection vulnerability',
            'path_traversal': 'Path Traversal vulnerability',
            'auth_bypass': 'Authentication Bypass vulnerability',
            'wp_xss': 'WordPress XSS vulnerability',
            'wp_sql_injection': 'WordPress SQL Injection',
            'wp_nonce_missing': 'Missing WordPress nonce verification',
            'wp_capability_check_missing': 'Missing capability check',
            'wp_csrf': 'WordPress CSRF vulnerability'
        }
        return descriptions.get(vuln_type, f'{vuln_type} vulnerability')

    def _get_full_description(self, vuln_type: str) -> str:
        """Get full description for vulnerability type."""
        descriptions = {
            'sql_injection': 'User input is used in SQL query without proper sanitization, allowing attackers to manipulate database queries.',
            'xss': 'User input is output without proper escaping, allowing attackers to inject malicious scripts.',
            'rce': 'User input is passed to dangerous functions like eval() or system(), allowing remote code execution.',
            'file_inclusion': 'User input is used in file inclusion functions, potentially allowing arbitrary file inclusion.',
            'command_injection': 'User input is passed to system command execution functions without sanitization.',
            'path_traversal': 'User input is used in file operations without path validation, allowing access to unauthorized files.',
            'auth_bypass': 'Authentication check uses unsafe comparison that may be bypassed.',
            'wp_xss': 'WordPress-specific XSS vulnerability where output is not escaped using WordPress functions.',
            'wp_sql_injection': 'WordPress database query uses unsanitized input without using $wpdb->prepare().',
        }
        return descriptions.get(vuln_type, f'Security vulnerability of type {vuln_type}')

    def _get_help(self, vuln_type: str) -> str:
        """Get help text for vulnerability type."""
        help_texts = {
            'sql_injection': 'Use prepared statements or sanitize input with intval() or mysqli_real_escape_string().',
            'xss': 'Escape output using htmlspecialchars() or similar functions.',
            'rce': 'Avoid using eval(), system(), exec() with user input. Use safe alternatives.',
            'file_inclusion': 'Validate file paths using basename() or realpath() and use allowlists.',
            'command_injection': 'Use escapeshellarg() and escapeshellcmd() or avoid shell execution entirely.',
            'path_traversal': 'Validate file paths with basename() and realpath().',
            'wp_xss': 'Use esc_html(), esc_attr(), or esc_url() before outputting data.',
            'wp_sql_injection': 'Use $wpdb->prepare() for all database queries with dynamic input.',
        }
        return help_texts.get(vuln_type, 'Consult security documentation for mitigation strategies.')

    def _get_tags(self, vuln_type: str) -> List[str]:
        """Get tags for vulnerability type."""
        base_tags = ['security', 'vulnerability']
        type_tags = {
            'sql_injection': ['sql', 'injection', 'database'],
            'xss': ['xss', 'injection', 'client-side'],
            'rce': ['rce', 'code-execution', 'critical'],
            'file_inclusion': ['file-inclusion', 'path-traversal'],
            'command_injection': ['command-injection', 'code-execution'],
            'wp_xss': ['wordpress', 'xss'],
            'wp_sql_injection': ['wordpress', 'sql', 'injection'],
        }
        return base_tags + type_tags.get(vuln_type, [vuln_type.split('_')])

    def _get_message(self, vuln: Dict) -> str:
        """Generate human-readable message for vulnerability."""
        vtype = vuln['type']
        sink = vuln.get('sink', 'unknown')

        if vuln.get('interprocedural'):
            return f"Inter-procedural {vtype} detected in {vuln.get('function', 'unknown')} via {sink}"
        else:
            return f"{vtype.replace('_', ' ').title()} detected at {sink}"
