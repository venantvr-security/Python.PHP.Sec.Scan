"""Production-ready FastAPI application."""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
import time

from api.routes import router
from core.config import load_config
from core.logger import setup_logging, get_logger
from core.exceptions import ScannerException

# Load configuration
config = load_config()

# Setup logging
setup_logging(
    level=config.logging.level,
    log_file=config.logging.file,
    format_type=config.logging.format
)

logger = get_logger('api.app')

# Create FastAPI app
app = FastAPI(
    title="PHP Security Scanner API",
    description="Production-ready PHP security vulnerability scanner",
    version="2.4.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.api.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests."""
    start_time = time.time()

    response = await call_next(request)

    duration = time.time() - start_time

    logger.info(
        f"{request.method} {request.url.path}",
        extra={
            'method': request.method,
            'path': request.url.path,
            'status_code': response.status_code,
            'duration': duration,
            'client_ip': request.client.host
        }
    )

    return response


# Exception handlers
@app.exception_handler(ScannerException)
async def scanner_exception_handler(request: Request, exc: ScannerException):
    """Handle scanner exceptions."""
    logger.error(f"Scanner error: {exc.message}", extra=exc.details)

    return JSONResponse(
        status_code=400,
        content={
            "error": exc.message,
            "details": exc.details
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(f"Unexpected error: {str(exc)}")

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": str(exc) if config.logging.level == 'DEBUG' else None
        }
    )


# Include routers
app.include_router(router)


# Startup/shutdown events
@app.on_event("startup")
async def startup_event():
    """Run on application startup."""
    logger.info("Starting PHP Security Scanner API")
    logger.info(f"Configuration: {config.logging.level} logging, cache: {config.cache.enabled}")


@app.on_event("shutdown")
async def shutdown_event():
    """Run on application shutdown."""
    logger.info("Shutting down PHP Security Scanner API")


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "PHP Security Scanner API",
        "version": "2.4.0",
        "status": "operational",
        "docs": "/api/docs"
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api.app:app",
        host=config.api.host,
        port=config.api.port,
        workers=config.api.workers,
        log_level=config.logging.level.lower()
    )
