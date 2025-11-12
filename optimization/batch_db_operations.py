# optimization/batch_db_operations.py
"""Batch database operations for improved performance."""

from typing import Dict

from sqlalchemy.orm import Session

from db.models import Vulnerability, Warning


class BatchInserter:
    """Batch insert operations for better database performance."""

    def __init__(self, session: Session, batch_size: int = 1000):
        self.session = session
        self.batch_size = batch_size
        self.vulnerability_buffer = []
        self.warning_buffer = []

    def add_vulnerability(self, vuln_data: Dict):
        """Add vulnerability to buffer."""
        self.vulnerability_buffer.append(vuln_data)

        if len(self.vulnerability_buffer) >= self.batch_size:
            self.flush_vulnerabilities()

    def add_warning(self, warning_data: Dict):
        """Add warning to buffer."""
        self.warning_buffer.append(warning_data)

        if len(self.warning_buffer) >= self.batch_size:
            self.flush_warnings()

    def flush_vulnerabilities(self):
        """Flush vulnerability buffer to database."""
        if not self.vulnerability_buffer:
            return

        # Bulk insert
        self.session.bulk_insert_mappings(Vulnerability, self.vulnerability_buffer)
        self.vulnerability_buffer.clear()

    def flush_warnings(self):
        """Flush warning buffer to database."""
        if not self.warning_buffer:
            return

        # Bulk insert
        self.session.bulk_insert_mappings(Warning, self.warning_buffer)
        self.warning_buffer.clear()

    def flush_all(self):
        """Flush all buffers."""
        self.flush_vulnerabilities()
        self.flush_warnings()
        self.session.commit()
