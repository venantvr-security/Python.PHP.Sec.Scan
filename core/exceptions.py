"""Custom exceptions for PHP security scanner."""


class ScannerException(Exception):
    """Base exception for all scanner errors."""

    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(ScannerException):
    """Configuration-related errors."""
    pass


class ScanError(ScannerException):
    """Errors during scanning process."""
    pass


class CacheError(ScannerException):
    """Cache-related errors."""
    pass


class ValidationError(ScannerException):
    """Input validation errors."""
    pass


class ParserError(ScannerException):
    """AST parsing errors."""
    pass


class AnalysisError(ScannerException):
    """Analysis/detection errors."""
    pass


class DatabaseError(ScannerException):
    """Database operation errors."""
    pass


class PluginError(ScannerException):
    """Plugin-related errors."""
    pass


class TimeoutError(ScannerException):
    """Timeout errors."""
    pass


class RateLimitError(ScannerException):
    """Rate limiting errors."""
    pass
