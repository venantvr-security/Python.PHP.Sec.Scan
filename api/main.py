# api/main.py
"""FastAPI REST API for PHP Security Scanner."""

import os
import tempfile
from typing import List, Optional

import tree_sitter_php as tsphp
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
from tree_sitter import Parser, Language

from db.connection import get_session
from db.models import Project, Scan, Vulnerability, ScanStatus
from exporters.sarif import SARIFExporter
from suppressions.manager import SuppressionManager
from workers.parallel_scanner import ParallelScanner

app = FastAPI(
    title="PHP Security Scanner API",
    description="REST API for static security analysis of PHP code",
    version="2.1.0"
)

# Initialize parser
PHP_LANGUAGE = Language(tsphp.language_php())
PARSER = Parser(PHP_LANGUAGE)


class ScanRequest(BaseModel):
    project_name: str
    root_path: str
    vuln_types: Optional[List[str]] = None
    workers: int = 12
    use_cache: bool = True


class ScanResponse(BaseModel):
    scan_id: int
    status: str
    message: str


class ProjectResponse(BaseModel):
    id: int
    name: str
    root_path: str
    is_wordpress: bool
    total_scans: int


class VulnerabilityResponse(BaseModel):
    id: int
    type: str
    file: str
    line: int
    severity: str
    sink: Optional[str] = None
    is_suppressed: bool = False


@app.get("/")
def read_root():
    """API root endpoint."""
    return {
        "name": "PHP Security Scanner API",
        "version": "2.1.0",
        "endpoints": {
            "projects": "/projects",
            "scans": "/scans",
            "scan": "/scan",
            "vulnerabilities": "/vulnerabilities/{scan_id}",
            "export": "/export/{scan_id}/sarif"
        }
    }


@app.get("/projects", response_model=List[ProjectResponse])
def list_projects():
    """List all projects."""
    with get_session() as session:
        projects = session.query(Project).all()
        return [
            {
                "id": p.id,
                "name": p.name,
                "root_path": p.root_path,
                "is_wordpress": p.is_wordpress,
                "total_scans": len(p.scans)
            }
            for p in projects
        ]


@app.get("/projects/{project_id}")
def get_project(project_id: int):
    """Get project details."""
    with get_session() as session:
        project = session.query(Project).filter_by(id=project_id).first()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        return {
            "id": project.id,
            "name": project.name,
            "root_path": project.root_path,
            "is_wordpress": project.is_wordpress,
            "created_at": project.created_at.isoformat(),
            "scans": [
                {
                    "id": scan.id,
                    "status": scan.status.value,
                    "total_vulnerabilities": scan.total_vulnerabilities,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None
                }
                for scan in project.scans
            ]
        }


@app.post("/scan", response_model=ScanResponse)
def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Create and run a new scan."""
    with get_session() as session:
        # Get or create project
        project = session.query(Project).filter_by(name=request.project_name).first()
        if not project:
            project = Project(
                name=request.project_name,
                root_path=request.root_path
            )
            session.add(project)
            session.flush()

        # Create scan
        vuln_types_str = ','.join(request.vuln_types) if request.vuln_types else 'all'
        scan = Scan(
            project_id=project.id,
            vuln_types=vuln_types_str,
            status=ScanStatus.PENDING
        )
        session.add(scan)
        session.flush()

        scan_id = scan.id

    # Run scan in background
    background_tasks.add_task(
        run_scan,
        scan_id,
        request.root_path,
        request.vuln_types,
        request.workers,
        request.use_cache
    )

    return {
        "scan_id": scan_id,
        "status": "pending",
        "message": "Scan queued successfully"
    }


def run_scan(scan_id: int, root_path: str, vuln_types: Optional[List[str]], workers: int, use_cache: bool):
    """Run scan in background."""
    from datetime import datetime, timezone

    with get_session() as session:
        scan = session.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        session.commit()

    try:
        # Find PHP files
        php_files = []
        for root, dirs, files in os.walk(root_path):
            for file in files:
                if file.endswith('.php'):
                    php_files.append(os.path.join(root, file))

        # Run scanner
        scanner = ParallelScanner(vuln_types or ['all'], max_workers=workers, use_cache=use_cache)
        results = scanner.scan_files(php_files)

        # Apply suppressions
        suppression_manager = SuppressionManager()
        active_vulns, suppressed_vulns = suppression_manager.filter_vulnerabilities(results)

        # Save to database
        with get_session() as session:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.total_vulnerabilities = len(active_vulns)
            scan.files_scanned = len(php_files)

            for vuln in active_vulns:
                vuln_obj = Vulnerability(
                    scan_id=scan_id,
                    vuln_type=vuln['type'],
                    file_path=vuln['file'],
                    line_number=vuln['line'],
                    column_number=vuln.get('column', 0),
                    severity=vuln.get('severity', 'medium'),
                    sink_function=vuln.get('sink'),
                    is_suppressed=False
                )
                session.add(vuln_obj)

            session.commit()

    except Exception as e:
        with get_session() as session:
            scan = session.query(Scan).filter_by(id=scan_id).first()
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            session.commit()


@app.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    """Get scan details."""
    with get_session() as session:
        scan = session.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        return {
            "id": scan.id,
            "project_id": scan.project_id,
            "status": scan.status.value,
            "vuln_types": scan.vuln_types,
            "total_vulnerabilities": scan.total_vulnerabilities,
            "files_scanned": scan.files_scanned,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_seconds": scan.duration_seconds
        }


@app.get("/vulnerabilities/{scan_id}", response_model=List[VulnerabilityResponse])
def get_vulnerabilities(scan_id: int, severity: Optional[str] = None):
    """Get vulnerabilities for a scan."""
    with get_session() as session:
        query = session.query(Vulnerability).filter_by(scan_id=scan_id)

        if severity:
            query = query.filter_by(severity=severity)

        vulns = query.all()

        return [
            {
                "id": v.id,
                "type": v.vuln_type,
                "file": v.file_path,
                "line": v.line_number,
                "severity": v.severity,
                "sink": v.sink_function,
                "is_suppressed": v.is_suppressed
            }
            for v in vulns
        ]


@app.get("/export/{scan_id}/sarif")
def export_sarif(scan_id: int):
    """Export scan results as SARIF."""
    with get_session() as session:
        scan = session.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        vulns = session.query(Vulnerability).filter_by(scan_id=scan_id).all()

        # Convert to dict format
        vuln_dicts = [
            {
                "type": v.vuln_type,
                "file": v.file_path,
                "line": v.line_number,
                "column": v.column_number,
                "severity": v.severity,
                "sink": v.sink_function
            }
            for v in vulns
        ]

        # Generate SARIF
        exporter = SARIFExporter()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
            temp_path = f.name

        exporter.export_to_file(vuln_dicts, temp_path)

        return FileResponse(
            temp_path,
            media_type='application/json',
            filename=f'scan_{scan_id}.sarif'
        )


@app.post("/suppressions/add")
def add_suppression(vulnerability_id: int, reason: str, author: str = "api"):
    """Add a suppression for a vulnerability."""
    with get_session() as session:
        vuln = session.query(Vulnerability).filter_by(id=vulnerability_id).first()
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")

        vuln_dict = {
            "type": vuln.vuln_type,
            "file": vuln.file_path,
            "line": vuln.line_number,
            "sink": vuln.sink_function
        }

        manager = SuppressionManager()
        manager.add_suppression(vuln_dict, reason, author)

        vuln.is_suppressed = True
        session.commit()

    return {"message": "Suppression added successfully"}


@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
