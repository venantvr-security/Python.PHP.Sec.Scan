# db/models.py
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey,
    Boolean, Enum, Index, Float, JSON
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class ScanStatus(PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnerabilitySeverity(PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text)
    repository_url = Column(String(512))
    root_path = Column(String(1024), nullable=False)

    # WordPress specific
    is_wordpress = Column(Boolean, default=False)
    wp_version = Column(String(50))

    # Metadata
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    suppressions = relationship("Suppression", back_populates="project", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Project(id={self.id}, name='{self.name}')>"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)

    # Scan configuration
    vuln_types = Column(JSON)  # List of vulnerability types to scan
    scan_mode = Column(String(50), default="full")  # full, incremental, diff
    git_commit_hash = Column(String(40))
    git_branch = Column(String(255))

    # Status
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration_seconds = Column(Float)

    # Statistics
    total_files = Column(Integer, default=0)
    scanned_files = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    total_warnings = Column(Integer, default=0)

    # Error handling
    error_message = Column(Text)

    # Metadata
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    triggered_by = Column(String(255))  # user, ci, scheduled, git-hook

    # Relationships
    project = relationship("Project", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    warnings = relationship("Warning", back_populates="scan", cascade="all, delete-orphan")
    files = relationship("File", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_scan_project_status', 'project_id', 'status'),
        Index('idx_scan_created', 'created_at'),
    )

    def __repr__(self):
        return f"<Scan(id={self.id}, project_id={self.project_id}, status={self.status.value})>"


class File(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)

    # File info
    filepath = Column(String(1024), nullable=False)
    file_hash = Column(String(64), index=True)  # SHA256 for caching
    lines_of_code = Column(Integer)

    # Analysis
    analyzed = Column(Boolean, default=False)
    analysis_duration_ms = Column(Float)
    ast_cached = Column(Boolean, default=False)

    # Statistics
    vulnerabilities_count = Column(Integer, default=0)
    warnings_count = Column(Integer, default=0)

    # Relationships
    scan = relationship("Scan", back_populates="files")

    __table_args__ = (
        Index('idx_file_scan_path', 'scan_id', 'filepath'),
        Index('idx_file_hash', 'file_hash'),
    )

    def __repr__(self):
        return f"<File(id={self.id}, filepath='{self.filepath}')>"


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)

    # Vulnerability details
    vuln_type = Column(String(100), nullable=False, index=True)  # sql_injection, xss, etc.
    severity = Column(Enum(VulnerabilitySeverity), default=VulnerabilitySeverity.MEDIUM, index=True)

    # Location
    filepath = Column(String(1024), nullable=False, index=True)
    line_number = Column(Integer, nullable=False)
    column_number = Column(Integer)

    # Details
    sink_function = Column(String(255))
    tainted_variable = Column(String(255))
    trace = Column(Text)  # Taint propagation trace
    code_snippet = Column(Text)

    # CWE mapping
    cwe_id = Column(String(20))
    cwe_description = Column(Text)

    # Suppression
    suppressed = Column(Boolean, default=False, index=True)
    suppression_reason = Column(Text)
    suppressed_by = Column(String(255))
    suppressed_at = Column(DateTime)

    # False positive detection
    is_false_positive = Column(Boolean)
    false_positive_confidence = Column(Float)  # ML confidence score

    # Metadata
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")

    __table_args__ = (
        Index('idx_vuln_scan_type', 'scan_id', 'vuln_type'),
        Index('idx_vuln_filepath_line', 'filepath', 'line_number'),
        Index('idx_vuln_suppressed', 'suppressed'),
    )

    def __repr__(self):
        return f"<Vulnerability(id={self.id}, type='{self.vuln_type}', file='{self.filepath}:{self.line_number}')>"


class Warning(Base):
    __tablename__ = "warnings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)

    # Warning details
    warning_type = Column(String(100), nullable=False, index=True)

    # Location
    filepath = Column(String(1024), nullable=False)
    line_number = Column(Integer, nullable=False)

    # Details
    function_name = Column(String(255))
    message = Column(Text)

    # Suppression
    suppressed = Column(Boolean, default=False)

    # Metadata
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="warnings")

    __table_args__ = (
        Index('idx_warning_scan_type', 'scan_id', 'warning_type'),
    )

    def __repr__(self):
        return f"<Warning(id={self.id}, type='{self.warning_type}')>"


class Suppression(Base):
    __tablename__ = "suppressions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)

    # Suppression criteria
    filepath = Column(String(1024))  # NULL = all files
    line_number = Column(Integer)  # NULL = all lines in file
    vuln_type = Column(String(100))  # NULL = all types

    # Suppression details
    reason = Column(Text, nullable=False)
    expires_at = Column(DateTime)  # NULL = never expires

    # Approval workflow
    created_by = Column(String(255), nullable=False)
    approved_by = Column(String(255))
    approved_at = Column(DateTime)

    # Metadata
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    active = Column(Boolean, default=True, index=True)

    # Relationships
    project = relationship("Project", back_populates="suppressions")

    __table_args__ = (
        Index('idx_suppression_project_active', 'project_id', 'active'),
        Index('idx_suppression_filepath', 'filepath'),
    )

    def __repr__(self):
        return f"<Suppression(id={self.id}, project_id={self.project_id})>"
