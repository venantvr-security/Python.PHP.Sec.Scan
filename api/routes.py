"""API routes for production scanner."""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from pathlib import Path

from core.exceptions import ValidationError, ScanError, RateLimitError
from core.rate_limiter import RateLimiter
from core.logger import get_logger
from core.validators import validate_directory, validate_vulnerability_types

logger = get_logger('api.routes')

# Router
router = APIRouter(prefix="/api/v1", tags=["scanner"])

# Rate limiter (100 requests/minute)
rate_limiter = RateLimiter(strategy='sliding_window', max_requests=100, window_seconds=60)


# Models
class ScanRequest(BaseModel):
    """Scan request model."""
    target: str = Field(..., description="Directory or file path to scan")
    vulnerability_types: List[str] = Field(
        default=["sql_injection", "xss", "rce"],
        description="Vulnerability types to scan for"
    )
    exclude_patterns: List[str] = Field(
        default=["vendor/", "node_modules/"],
        description="Patterns to exclude"
    )
    max_workers: Optional[int] = Field(default=None, description="Number of parallel workers")
    use_cache: bool = Field(default=True, description="Enable caching")

    @validator('target')
    def validate_target(cls, v):
        if not v:
            raise ValueError("Target path is required")
        return v

    @validator('vulnerability_types')
    def validate_vuln_types(cls, v):
        if not v:
            raise ValueError("At least one vulnerability type required")
        return v


class ScanResponse(BaseModel):
    """Scan response model."""
    scan_id: str
    status: str
    message: str


class ScanStatus(BaseModel):
    """Scan status model."""
    scan_id: str
    status: str
    progress: float
    total_files: int
    scanned_files: int
    vulnerabilities_found: int


class VulnerabilityResponse(BaseModel):
    """Vulnerability response model."""
    id: str
    type: str
    severity: str
    file: str
    line: int
    description: str
    cwe_id: Optional[int]
    remediation: Optional[str]


class ScanResultsResponse(BaseModel):
    """Scan results response model."""
    scan_id: str
    status: str
    statistics: dict
    vulnerabilities: List[VulnerabilityResponse]


# Dependency for rate limiting
async def check_rate_limit(request: Request):
    """Check rate limit for request."""
    client_ip = request.client.host
    key = RateLimiter.generate_key(client_ip)

    try:
        rate_limiter.check_limit(key)
    except RateLimitError as e:
        raise HTTPException(
            status_code=429,
            detail={"error": "Rate limit exceeded", "details": e.details}
        )


# Routes
@router.post("/scan", response_model=ScanResponse, dependencies=[Depends(check_rate_limit)])
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Create a new security scan.

    - **target**: Directory or file path to scan
    - **vulnerability_types**: Types of vulnerabilities to detect
    - **exclude_patterns**: File patterns to exclude
    - **max_workers**: Number of parallel workers (optional)
    - **use_cache**: Enable result caching
    """
    try:
        # Validate input
        target_path = validate_directory(scan_request.target)
        vuln_types = validate_vulnerability_types(scan_request.vulnerability_types)

        # Generate scan ID
        import uuid
        scan_id = str(uuid.uuid4())

        # Queue scan in background
        background_tasks.add_task(
            run_scan,
            scan_id,
            str(target_path),
            vuln_types,
            scan_request.exclude_patterns,
            scan_request.max_workers,
            scan_request.use_cache
        )

        logger.info(f"Scan created: {scan_id}", extra={'scan_id': scan_id, 'target': str(target_path)})

        return ScanResponse(
            scan_id=scan_id,
            status="queued",
            message=f"Scan {scan_id} has been queued"
        )

    except ValidationError as e:
        logger.warning(f"Validation error: {e.message}", extra=e.details)
        raise HTTPException(status_code=400, detail={"error": e.message, "details": e.details})
    except Exception as e:
        logger.error(f"Scan creation failed: {str(e)}")
        raise HTTPException(status_code=500, detail={"error": "Internal server error"})


@router.get("/scan/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """
    Get scan status.

    Returns current progress and statistics.
    """
    try:
        # TODO: Implement actual status lookup
        return ScanStatus(
            scan_id=scan_id,
            status="running",
            progress=0.5,
            total_files=100,
            scanned_files=50,
            vulnerabilities_found=5
        )
    except Exception as e:
        logger.error(f"Status lookup failed: {str(e)}")
        raise HTTPException(status_code=404, detail={"error": "Scan not found"})


@router.get("/scan/{scan_id}/results", response_model=ScanResultsResponse)
async def get_scan_results(scan_id: str):
    """
    Get scan results.

    Returns complete vulnerability report.
    """
    try:
        # TODO: Implement actual results lookup
        return ScanResultsResponse(
            scan_id=scan_id,
            status="completed",
            statistics={
                "total_files": 100,
                "total_vulnerabilities": 5,
                "scan_time": 30.5
            },
            vulnerabilities=[]
        )
    except Exception as e:
        logger.error(f"Results lookup failed: {str(e)}")
        raise HTTPException(status_code=404, detail={"error": "Results not found"})


@router.delete("/scan/{scan_id}")
async def cancel_scan(scan_id: str):
    """
    Cancel a running scan.
    """
    try:
        # TODO: Implement scan cancellation
        logger.info(f"Scan cancelled: {scan_id}")
        return {"message": f"Scan {scan_id} cancelled"}
    except Exception as e:
        logger.error(f"Cancellation failed: {str(e)}")
        raise HTTPException(status_code=500, detail={"error": "Cancellation failed"})


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "php-security-scanner"}


@router.get("/metrics")
async def get_metrics():
    """
    Get scanner metrics.

    Returns system statistics and performance metrics.
    """
    # TODO: Implement actual metrics collection
    return {
        "total_scans": 0,
        "active_scans": 0,
        "cache_hit_rate": 0.0,
        "avg_scan_time": 0.0
    }


# Background task
async def run_scan(
    scan_id: str,
    target: str,
    vuln_types: List[str],
    exclude_patterns: List[str],
    max_workers: Optional[int],
    use_cache: bool
):
    """Run scan in background."""
    try:
        logger.info(f"Starting scan: {scan_id}")

        # TODO: Implement actual scan execution
        # from workers.parallel_scanner import ParallelScanner
        # scanner = ParallelScanner(...)
        # results = scanner.scan_directory(target)

        logger.info(f"Scan completed: {scan_id}")

    except Exception as e:
        logger.error(f"Scan failed: {scan_id} - {str(e)}")
