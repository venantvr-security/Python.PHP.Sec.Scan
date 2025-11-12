"""Mock Config for BDD tests."""

class MockPerformance:
    def __init__(self):
        self.max_workers = 32

class MockCache:
    def __init__(self):
        self.enabled = True
        self.backend = 'disk'
        self.redis_url = None

class MockDatabase:
    def __init__(self):
        self.url = None

class MockScan:
    def __init__(self):
        self.max_file_size = 1048576  # 1MB

class MockConfig:
    """Mock configuration for tests."""

    def __init__(self):
        self.performance = MockPerformance()
        self.cache = MockCache()
        self.database = MockDatabase()
        self.scan = MockScan()
        self.log_level = 'INFO'

        # Also add flat attributes for backward compatibility
        self.cache_enabled = True
        self.max_workers = 32
        self.cache_backend = 'disk'
        self.redis_url = None
        self.database_url = None

    @classmethod
    def from_yaml(cls, filepath):
        """Load from YAML file."""
        import yaml
        config = cls()
        try:
            with open(filepath) as f:
                data = yaml.safe_load(f)
                if 'performance' in data:
                    config.performance.max_workers = data['performance'].get('max_workers', 32)
                    config.max_workers = config.performance.max_workers
                if 'cache' in data:
                    config.cache.enabled = data['cache'].get('enabled', True)
                    config.cache.backend = data['cache'].get('backend', 'disk')
                    config.cache.redis_url = data['cache'].get('redis_url')
                    config.cache_enabled = config.cache.enabled
                    config.cache_backend = config.cache.backend
                    config.redis_url = config.cache.redis_url
        except:
            pass
        return config

    @classmethod
    def from_env(cls):
        """Load from environment variables."""
        import os
        config = cls()
        if 'MAX_WORKERS' in os.environ:
            config.performance.max_workers = int(os.environ['MAX_WORKERS'])
            config.max_workers = config.performance.max_workers
        if 'CACHE_ENABLED' in os.environ:
            config.cache.enabled = os.environ['CACHE_ENABLED'].lower() == 'true'
            config.cache_enabled = config.cache.enabled
        if 'CACHE_BACKEND' in os.environ:
            config.cache.backend = os.environ['CACHE_BACKEND']
            config.cache_backend = config.cache.backend
        if 'REDIS_URL' in os.environ:
            config.cache.redis_url = os.environ['REDIS_URL']
            config.redis_url = config.cache.redis_url
        if 'DATABASE_URL' in os.environ:
            config.database.url = os.environ['DATABASE_URL']
            config.database_url = config.database.url
        return config

    @classmethod
    def from_dict(cls, data):
        """Load from dict."""
        config = cls()
        if 'performance' in data:
            config.performance.max_workers = data['performance'].get('max_workers', 32)
            config.max_workers = config.performance.max_workers
        if 'cache' in data:
            config.cache.enabled = data['cache'].get('enabled', True)
            config.cache.backend = data['cache'].get('backend', 'disk')
            config.cache.redis_url = data['cache'].get('redis_url')
            config.cache_enabled = config.cache.enabled
            config.cache_backend = config.cache.backend
            config.redis_url = config.cache.redis_url
        if 'database' in data:
            config.database.url = data['database'].get('url')
            config.database_url = config.database.url
        return config

    def validate(self):
        """Validate configuration."""
        if self.cache_backend == 'redis' and not self.redis_url:
            raise ValueError("Redis backend requires redis_url")
        if self.max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        return True
