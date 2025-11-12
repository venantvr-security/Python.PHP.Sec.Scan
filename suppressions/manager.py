# suppressions/manager.py
"""Manage vulnerability suppressions and allowlists."""

import json
import yaml
from typing import List, Dict, Set, Optional
from pathlib import Path
import hashlib


class SuppressionManager:
    """Manage suppressed vulnerabilities."""

    def __init__(self, suppression_file: Optional[str] = None):
        self.suppression_file = suppression_file or ".scanner-suppressions.yaml"
        self.suppressions: List[Dict] = []
        self.load()

    def load(self):
        """Load suppressions from file."""
        if not Path(self.suppression_file).exists():
            return

        with open(self.suppression_file, 'r') as f:
            data = yaml.safe_load(f) or {}
            self.suppressions = data.get('suppressions', [])

    def save(self):
        """Save suppressions to file."""
        data = {'suppressions': self.suppressions}
        with open(self.suppression_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)

    def is_suppressed(self, vulnerability: Dict) -> bool:
        """Check if vulnerability is suppressed."""
        for suppression in self.suppressions:
            if self._matches(vulnerability, suppression):
                return True
        return False

    def _matches(self, vulnerability: Dict, suppression: Dict) -> bool:
        """Check if vulnerability matches suppression rule."""
        # Match by fingerprint (most specific)
        if 'fingerprint' in suppression:
            vuln_fingerprint = self._generate_fingerprint(vulnerability)
            if vuln_fingerprint == suppression['fingerprint']:
                return True

        # Match by location and type
        if 'file' in suppression and 'line' in suppression and 'type' in suppression:
            if (vulnerability['file'].endswith(suppression['file']) and
                vulnerability['line'] == suppression['line'] and
                vulnerability['type'] == suppression['type']):
                return True

        # Match by pattern
        if 'pattern' in suppression:
            pattern = suppression['pattern']
            if 'file' in pattern and not vulnerability['file'].endswith(pattern['file']):
                return False
            if 'type' in pattern and vulnerability['type'] != pattern['type']:
                return False
            if 'sink' in pattern and vulnerability.get('sink') != pattern['sink']:
                return False
            return True

        return False

    def add_suppression(self, vulnerability: Dict, reason: str, author: str = "unknown"):
        """Add a suppression for a vulnerability."""
        suppression = {
            'fingerprint': self._generate_fingerprint(vulnerability),
            'type': vulnerability['type'],
            'file': vulnerability['file'],
            'line': vulnerability['line'],
            'reason': reason,
            'author': author,
            'added_at': self._get_timestamp()
        }
        self.suppressions.append(suppression)
        self.save()

    def add_pattern_suppression(self, pattern: Dict, reason: str, author: str = "unknown"):
        """Add a pattern-based suppression."""
        suppression = {
            'pattern': pattern,
            'reason': reason,
            'author': author,
            'added_at': self._get_timestamp()
        }
        self.suppressions.append(suppression)
        self.save()

    def remove_suppression(self, fingerprint: str) -> bool:
        """Remove a suppression by fingerprint."""
        original_len = len(self.suppressions)
        self.suppressions = [s for s in self.suppressions if s.get('fingerprint') != fingerprint]

        if len(self.suppressions) < original_len:
            self.save()
            return True
        return False

    def filter_vulnerabilities(self, vulnerabilities: List[Dict]) -> tuple[List[Dict], List[Dict]]:
        """Filter vulnerabilities, returning (active, suppressed)."""
        active = []
        suppressed = []

        for vuln in vulnerabilities:
            if self.is_suppressed(vuln):
                suppressed.append(vuln)
            else:
                active.append(vuln)

        return active, suppressed

    def _generate_fingerprint(self, vulnerability: Dict) -> str:
        """Generate unique fingerprint for vulnerability."""
        content = f"{vulnerability['type']}:{vulnerability['file']}:{vulnerability['line']}:{vulnerability.get('sink', '')}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _get_timestamp(self) -> str:
        """Get current timestamp."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    def get_statistics(self) -> Dict:
        """Get suppression statistics."""
        stats = {
            'total_suppressions': len(self.suppressions),
            'by_type': {},
            'by_author': {}
        }

        for suppression in self.suppressions:
            # Count by type
            vtype = suppression.get('type', 'unknown')
            stats['by_type'][vtype] = stats['by_type'].get(vtype, 0) + 1

            # Count by author
            author = suppression.get('author', 'unknown')
            stats['by_author'][author] = stats['by_author'].get(author, 0) + 1

        return stats


class AllowlistManager:
    """Manage allowlisted patterns."""

    def __init__(self, allowlist_file: Optional[str] = None):
        self.allowlist_file = allowlist_file or ".scanner-allowlist.yaml"
        self.patterns: List[Dict] = []
        self.load()

    def load(self):
        """Load allowlist from file."""
        if not Path(self.allowlist_file).exists():
            return

        with open(self.allowlist_file, 'r') as f:
            data = yaml.safe_load(f) or {}
            self.patterns = data.get('patterns', [])

    def save(self):
        """Save allowlist to file."""
        data = {'patterns': self.patterns}
        with open(self.allowlist_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)

    def is_allowed(self, vulnerability: Dict) -> bool:
        """Check if vulnerability is in allowlist."""
        for pattern in self.patterns:
            if self._matches_pattern(vulnerability, pattern):
                return True
        return False

    def _matches_pattern(self, vulnerability: Dict, pattern: Dict) -> bool:
        """Check if vulnerability matches allowlist pattern."""
        if 'file_pattern' in pattern:
            import re
            if not re.search(pattern['file_pattern'], vulnerability['file']):
                return False

        if 'type' in pattern and vulnerability['type'] != pattern['type']:
            return False

        if 'sink_pattern' in pattern:
            import re
            sink = vulnerability.get('sink', '')
            if not re.search(pattern['sink_pattern'], sink):
                return False

        return True

    def add_pattern(self, pattern: Dict, reason: str):
        """Add pattern to allowlist."""
        entry = {
            **pattern,
            'reason': reason,
            'added_at': self._get_timestamp()
        }
        self.patterns.append(entry)
        self.save()

    def _get_timestamp(self) -> str:
        """Get current timestamp."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
