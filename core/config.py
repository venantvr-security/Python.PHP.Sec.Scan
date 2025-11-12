"""Configuration management for production scanner."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional, Any
import yaml
from dotenv import load_dotenv

from core.exceptions import ConfigurationError


@dataclass
class ScanConfig:
    """Scan configuration."""
    vulnerability_types: List[str] = field(default_factory=lambda: [
        'sql_injection', 'xss', 'rce', 'file_inclusion',
        'command_injection', 'path_traversal'
    ])
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    exclude_patterns: List[str] = field(default_factory=lambda: [
        'vendor/', 'node_modules/', 'cache/', '.git/'
    ])
    file_extensions: List[str] = field(default_factory=lambda: ['.php'])
    timeout_per_file: int = 30  # seconds


@dataclass
class CacheConfig:
    """Cache configuration."""
    enabled: bool = True
    backend: str = 'disk'  # disk or redis
    ttl: int = 86400  # 24 hours
    size_limit: int = 1024**3  # 1GB
    redis_url: Optional[str] = None


@dataclass
class DatabaseConfig:
    """Database configuration."""
    enabled: bool = True
    url: str = 'sqlite:///scanner.db'
    pool_size: int = 5
    max_overflow: int = 10


@dataclass
class APIConfig:
    """API configuration."""
    enabled: bool = False
    host: str = '0.0.0.0'
    port: int = 8000
    workers: int = 4
    cors_origins: List[str] = field(default_factory=lambda: ['*'])
    rate_limit: str = '100/minute'


@dataclass
class PerformanceConfig:
    """Performance configuration."""
    max_workers: int = 32
    chunk_size: int = 100
    use_adaptive_workers: bool = True


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = 'INFO'
    format: str = 'json'
    file: Optional[str] = None


@dataclass
class Config:
    """Main configuration object."""
    scan: ScanConfig = field(default_factory=ScanConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    api: APIConfig = field(default_factory=APIConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Config':
        """Create Config from dictionary."""
        return cls(
            scan=ScanConfig(**data.get('scan', {})),
            cache=CacheConfig(**data.get('cache', {})),
            database=DatabaseConfig(**data.get('database', {})),
            api=APIConfig(**data.get('api', {})),
            performance=PerformanceConfig(**data.get('performance', {})),
            logging=LoggingConfig(**data.get('logging', {}))
        )

    @classmethod
    def from_yaml(cls, path: str) -> 'Config':
        """Load configuration from YAML file."""
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            return cls.from_dict(data)
        except FileNotFoundError:
            raise ConfigurationError(f"Config file not found: {path}")
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML: {e}")

    @classmethod
    def from_env(cls) -> 'Config':
        """Load configuration from environment variables."""
        load_dotenv()

        return cls(
            scan=ScanConfig(
                vulnerability_types=os.getenv('SCAN_VULN_TYPES', '').split(',') or ScanConfig().vulnerability_types,
                max_file_size=int(os.getenv('SCAN_MAX_FILE_SIZE', '10485760')),
            ),
            cache=CacheConfig(
                enabled=os.getenv('CACHE_ENABLED', 'true').lower() == 'true',
                backend=os.getenv('CACHE_BACKEND', 'disk'),
                redis_url=os.getenv('REDIS_URL'),
            ),
            database=DatabaseConfig(
                enabled=os.getenv('DB_ENABLED', 'true').lower() == 'true',
                url=os.getenv('DATABASE_URL', 'sqlite:///scanner.db'),
            ),
            api=APIConfig(
                enabled=os.getenv('API_ENABLED', 'false').lower() == 'true',
                host=os.getenv('API_HOST', '0.0.0.0'),
                port=int(os.getenv('API_PORT', '8000')),
            ),
            performance=PerformanceConfig(
                max_workers=int(os.getenv('MAX_WORKERS', '32')),
            ),
            logging=LoggingConfig(
                level=os.getenv('LOG_LEVEL', 'INFO'),
                format=os.getenv('LOG_FORMAT', 'json'),
                file=os.getenv('LOG_FILE'),
            )
        )

    def validate(self) -> None:
        """Validate configuration."""
        if self.scan.max_file_size <= 0:
            raise ConfigurationError("max_file_size must be positive")

        if self.performance.max_workers <= 0:
            raise ConfigurationError("max_workers must be positive")

        if self.cache.enabled and self.cache.backend == 'redis' and not self.cache.redis_url:
            raise ConfigurationError("redis_url required when using redis cache")


def load_config(config_path: Optional[str] = None) -> Config:
    """
    Load configuration with priority:
    1. Provided config file path
    2. CONFIG_PATH environment variable
    3. config.yaml in current directory
    4. Environment variables
    5. Defaults
    """
    if config_path:
        config = Config.from_yaml(config_path)
    elif 'CONFIG_PATH' in os.environ:
        config = Config.from_yaml(os.environ['CONFIG_PATH'])
    elif Path('config.yaml').exists():
        config = Config.from_yaml('config.yaml')
    else:
        config = Config.from_env()

    config.validate()
    return config
