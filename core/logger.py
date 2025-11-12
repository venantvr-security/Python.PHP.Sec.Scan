"""Structured logging for production environment."""

import logging
import sys
from pathlib import Path
from typing import Optional
import json
from datetime import datetime


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }

        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        if hasattr(record, 'extra_data'):
            log_data['extra'] = record.extra_data

        return json.dumps(log_data)


def setup_logging(
    level: str = 'INFO',
    log_file: Optional[str] = None,
    format_type: str = 'json',
    app_name: str = 'php-security-scanner'
) -> logging.Logger:
    """
    Setup structured logging for production.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        format_type: 'json' or 'text'
        app_name: Application name for logger

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(app_name)
    logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)

    if format_type == 'json':
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        )

    logger.addHandler(console_handler)

    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(JSONFormatter())
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get logger instance."""
    return logging.getLogger(f'php-security-scanner.{name}')


class LogContext:
    """Context manager for adding extra data to logs."""

    def __init__(self, logger: logging.Logger, **kwargs):
        self.logger = logger
        self.extra_data = kwargs
        self.old_factory = None

    def __enter__(self):
        old_factory = logging.getLogRecordFactory()

        def record_factory(*args, **kwargs):
            record = old_factory(*args, **kwargs)
            record.extra_data = self.extra_data
            return record

        logging.setLogRecordFactory(record_factory)
        self.old_factory = old_factory
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.old_factory:
            logging.setLogRecordFactory(self.old_factory)
