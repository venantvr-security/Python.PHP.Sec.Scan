"""Advanced detection engine with improved accuracy."""

from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass
from enum import Enum

from tree_sitter import Node


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(Enum):
    """Detection confidence levels."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class DetectionRule:
    """Vulnerability detection rule."""
    id: str
    name: str
    vuln_type: str
    severity: Severity
    description: str
    cwe_id: Optional[int] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None

    # Pattern matching
    sources: List[Dict[str, Any]] = None
    sinks: List[Dict[str, Any]] = None
    sanitizers: List[Dict[str, Any]] = None

    def __post_init__(self):
        if self.sources is None:
            self.sources = []
        if self.sinks is None:
            self.sinks = []
        if self.sanitizers is None:
            self.sanitizers = []


class DetectionEngine:
    """Advanced vulnerability detection engine."""

    # Extended vulnerability patterns
    DETECTION_RULES = {
        'sql_injection': DetectionRule(
            id='SEC001',
            name='SQL Injection',
            vuln_type='sql_injection',
            severity=Severity.CRITICAL,
            description='Unvalidated input used in SQL query',
            cwe_id=89,
            owasp_category='A03:2021 – Injection',
            remediation='Use prepared statements with parameterized queries',
            sources=[
                {'type': 'superglobal', 'names': ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']},
                {'type': 'function', 'names': ['file_get_contents', 'fgets', 'curl_exec']},
            ],
            sinks=[
                {'function': 'mysql_query', 'params': [0]},
                {'function': 'mysqli_query', 'params': [1]},
                {'function': 'pg_query', 'params': [0]},
                {'function': 'mssql_query', 'params': [0]},
                {'method': 'query', 'params': [0]},
                {'method': 'exec', 'params': [0]},
            ],
            sanitizers=[
                {'function': 'mysqli_real_escape_string'},
                {'function': 'pg_escape_string'},
                {'method': 'prepare'},
                {'method': 'quote'},
            ]
        ),

        'xss': DetectionRule(
            id='SEC002',
            name='Cross-Site Scripting (XSS)',
            vuln_type='xss',
            severity=Severity.HIGH,
            description='Unescaped user input in output',
            cwe_id=79,
            owasp_category='A03:2021 – Injection',
            remediation='Escape all user-controlled output using htmlspecialchars() or similar',
            sources=[
                {'type': 'superglobal', 'names': ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']},
            ],
            sinks=[
                {'statement': 'echo'},
                {'statement': 'print'},
                {'function': 'printf'},
                {'function': 'vprintf'},
            ],
            sanitizers=[
                {'function': 'htmlspecialchars'},
                {'function': 'htmlentities'},
                {'function': 'esc_html'},
                {'function': 'esc_attr'},
                {'function': 'esc_url'},
            ]
        ),

        'rce': DetectionRule(
            id='SEC003',
            name='Remote Code Execution',
            vuln_type='rce',
            severity=Severity.CRITICAL,
            description='User input passed to code execution function',
            cwe_id=94,
            owasp_category='A03:2021 – Injection',
            remediation='Avoid using dangerous functions with user input',
            sources=[
                {'type': 'superglobal', 'names': ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']},
            ],
            sinks=[
                {'function': 'eval'},
                {'function': 'exec'},
                {'function': 'system'},
                {'function': 'shell_exec'},
                {'function': 'passthru'},
                {'function': 'popen'},
                {'function': 'proc_open'},
                {'function': 'pcntl_exec'},
                {'function': 'assert'},
                {'function': 'create_function'},
                {'function': 'preg_replace', 'params': [0], 'condition': '/e modifier'},
            ],
            sanitizers=[
                {'function': 'escapeshellarg'},
                {'function': 'escapeshellcmd'},
            ]
        ),

        'file_inclusion': DetectionRule(
            id='SEC004',
            name='File Inclusion',
            vuln_type='file_inclusion',
            severity=Severity.HIGH,
            description='User input used in file inclusion',
            cwe_id=98,
            owasp_category='A05:2021 – Security Misconfiguration',
            remediation='Use allowlist of permitted files, validate with realpath()',
            sources=[
                {'type': 'superglobal', 'names': ['$_GET', '$_POST', '$_REQUEST']},
            ],
            sinks=[
                {'statement': 'include'},
                {'statement': 'include_once'},
                {'statement': 'require'},
                {'statement': 'require_once'},
            ],
            sanitizers=[
                {'function': 'basename'},
                {'function': 'realpath'},
            ]
        ),

        'path_traversal': DetectionRule(
            id='SEC005',
            name='Path Traversal',
            vuln_type='path_traversal',
            severity=Severity.HIGH,
            description='User input used in file operations without validation',
            cwe_id=22,
            owasp_category='A01:2021 – Broken Access Control',
            remediation='Validate file paths with realpath() and check against base directory',
            sources=[
                {'type': 'superglobal', 'names': ['$_GET', '$_POST', '$_REQUEST']},
            ],
            sinks=[
                {'function': 'file_get_contents'},
                {'function': 'file_put_contents'},
                {'function': 'fopen'},
                {'function': 'readfile'},
                {'function': 'unlink'},
                {'function': 'copy'},
                {'function': 'rename'},
                {'function': 'rmdir'},
                {'function': 'mkdir'},
            ],
            sanitizers=[
                {'function': 'basename'},
                {'function': 'realpath'},
            ]
        ),

        'deserialization': DetectionRule(
            id='SEC006',
            name='Unsafe Deserialization',
            vuln_type='deserialization',
            severity=Severity.CRITICAL,
            description='Untrusted data deserialized',
            cwe_id=502,
            owasp_category='A08:2021 – Software and Data Integrity Failures',
            remediation='Avoid unserialize() with untrusted data, use JSON instead',
            sources=[
                {'type': 'superglobal', 'names': ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']},
            ],
            sinks=[
                {'function': 'unserialize'},
                {'function': 'yaml_parse'},
            ],
            sanitizers=[]
        ),

        'xxe': DetectionRule(
            id='SEC007',
            name='XML External Entity (XXE)',
            vuln_type='xxe',
            severity=Severity.HIGH,
            description='XML parser allows external entities',
            cwe_id=611,
            owasp_category='A05:2021 – Security Misconfiguration',
            remediation='Disable external entity loading in XML parsers',
            sources=[
                {'type': 'superglobal', 'names': ['$_POST', '$_REQUEST']},
            ],
            sinks=[
                {'function': 'simplexml_load_string'},
                {'function': 'simplexml_load_file'},
                {'method': 'loadXML'},
            ],
            sanitizers=[]
        ),

        'ssrf': DetectionRule(
            id='SEC008',
            name='Server-Side Request Forgery (SSRF)',
            vuln_type='ssrf',
            severity=Severity.HIGH,
            description='User input used in URL for server-side request',
            cwe_id=918,
            owasp_category='A10:2021 – Server-Side Request Forgery',
            remediation='Validate URLs against allowlist, disable URL wrappers',
            sources=[
                {'type': 'superglobal', 'names': ['$_GET', '$_POST', '$_REQUEST']},
            ],
            sinks=[
                {'function': 'file_get_contents'},
                {'function': 'curl_exec'},
                {'function': 'fopen'},
            ],
            sanitizers=[
                {'function': 'filter_var', 'params': [1], 'condition': 'FILTER_VALIDATE_URL'},
            ]
        ),

        'open_redirect': DetectionRule(
            id='SEC009',
            name='Open Redirect',
            vuln_type='open_redirect',
            severity=Severity.MEDIUM,
            description='User input used in redirect location',
            cwe_id=601,
            owasp_category='A01:2021 – Broken Access Control',
            remediation='Validate redirect URLs against allowlist',
            sources=[
                {'type': 'superglobal', 'names': ['$_GET', '$_POST', '$_REQUEST']},
            ],
            sinks=[
                {'function': 'header', 'condition': 'Location:'},
            ],
            sanitizers=[]
        ),

        'ldap_injection': DetectionRule(
            id='SEC010',
            name='LDAP Injection',
            vuln_type='ldap_injection',
            severity=Severity.HIGH,
            description='User input used in LDAP query',
            cwe_id=90,
            owasp_category='A03:2021 – Injection',
            remediation='Escape LDAP special characters',
            sources=[
                {'type': 'superglobal', 'names': ['$_GET', '$_POST', '$_REQUEST']},
            ],
            sinks=[
                {'function': 'ldap_search'},
                {'function': 'ldap_list'},
                {'function': 'ldap_read'},
            ],
            sanitizers=[
                {'function': 'ldap_escape'},
            ]
        ),
    }

    @classmethod
    def get_rule(cls, vuln_type: str) -> Optional[DetectionRule]:
        """Get detection rule by vulnerability type."""
        return cls.DETECTION_RULES.get(vuln_type)

    @classmethod
    def get_all_rules(cls) -> Dict[str, DetectionRule]:
        """Get all detection rules."""
        return cls.DETECTION_RULES.copy()

    @classmethod
    def get_severity(cls, vuln_type: str) -> Severity:
        """Get severity for vulnerability type."""
        rule = cls.get_rule(vuln_type)
        return rule.severity if rule else Severity.MEDIUM

    @classmethod
    def get_cwe_id(cls, vuln_type: str) -> Optional[int]:
        """Get CWE ID for vulnerability type."""
        rule = cls.get_rule(vuln_type)
        return rule.cwe_id if rule else None

    @classmethod
    def calculate_confidence(
        cls,
        has_sanitization: bool,
        has_validation: bool,
        context_analysis: bool
    ) -> Confidence:
        """
        Calculate confidence level for detection.

        Args:
            has_sanitization: Whether sanitization was found
            has_validation: Whether validation was found
            context_analysis: Whether context analysis was performed

        Returns:
            Confidence level
        """
        if has_sanitization or has_validation:
            return Confidence.LOW

        if context_analysis:
            return Confidence.HIGH

        return Confidence.MEDIUM
