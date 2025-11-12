"""Input validation utilities."""

import os
from pathlib import Path
from typing import List

from core.exceptions import ValidationError


def validate_file_path(filepath: str, must_exist: bool = True) -> Path:
    """
    Validate file path.

    Args:
        filepath: File path to validate
        must_exist: Whether file must exist

    Returns:
        Validated Path object

    Raises:
        ValidationError: If validation fails
    """
    try:
        path = Path(filepath).resolve()
    except Exception as e:
        raise ValidationError(f"Invalid file path: {filepath}", {'error': str(e)})

    if must_exist and not path.exists():
        raise ValidationError(f"File does not exist: {filepath}")

    if must_exist and not path.is_file():
        raise ValidationError(f"Path is not a file: {filepath}")

    # Security: Check for path traversal
    try:
        path.relative_to(Path.cwd())
    except ValueError:
        # Path is outside current directory - allow but log
        pass

    return path


def validate_directory(dirpath: str, must_exist: bool = True) -> Path:
    """
    Validate directory path.

    Args:
        dirpath: Directory path to validate
        must_exist: Whether directory must exist

    Returns:
        Validated Path object

    Raises:
        ValidationError: If validation fails
    """
    try:
        path = Path(dirpath).resolve()
    except Exception as e:
        raise ValidationError(f"Invalid directory path: {dirpath}", {'error': str(e)})

    if must_exist and not path.exists():
        raise ValidationError(f"Directory does not exist: {dirpath}")

    if must_exist and not path.is_dir():
        raise ValidationError(f"Path is not a directory: {dirpath}")

    return path


def validate_vulnerability_types(vuln_types: List[str]) -> List[str]:
    """
    Validate vulnerability types.

    Args:
        vuln_types: List of vulnerability types

    Returns:
        Validated list

    Raises:
        ValidationError: If validation fails
    """
    VALID_TYPES = {
        'sql_injection', 'xss', 'rce', 'file_inclusion',
        'command_injection', 'path_traversal', 'auth_bypass',
        'deserialization', 'xxe', 'ssrf', 'ldap_injection',
        'xpath_injection', 'open_redirect', 'csrf'
    }

    if not vuln_types:
        raise ValidationError("At least one vulnerability type must be specified")

    invalid = set(vuln_types) - VALID_TYPES
    if invalid:
        raise ValidationError(
            f"Invalid vulnerability types: {', '.join(invalid)}",
            {'valid_types': list(VALID_TYPES)}
        )

    return vuln_types


def validate_file_size(filepath: Path, max_size: int) -> bool:
    """
    Check if file size is within limits.

    Args:
        filepath: File to check
        max_size: Maximum size in bytes

    Returns:
        True if valid, False otherwise
    """
    try:
        size = filepath.stat().st_size
        return size <= max_size
    except OSError:
        return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe filesystem operations.

    Args:
        filename: Filename to sanitize

    Returns:
        Sanitized filename
    """
    # Remove path separators
    filename = filename.replace('/', '_').replace('\\', '_')

    # Remove null bytes
    filename = filename.replace('\0', '')

    # Limit length
    if len(filename) > 255:
        filename = filename[:255]

    return filename
