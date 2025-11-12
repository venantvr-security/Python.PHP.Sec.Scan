"""Monitoring and observability for production."""

import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
from threading import Lock
import psutil
import os

from core.logger import get_logger

logger = get_logger('monitoring')


@dataclass
class MetricValue:
    """Single metric value with timestamp."""
    value: float
    timestamp: float = field(default_factory=time.time)
    labels: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """Collect and expose metrics for monitoring."""

    def __init__(self):
        self.counters: Dict[str, float] = defaultdict(float)
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.lock = Lock()

    def increment_counter(self, name: str, value: float = 1.0, labels: Dict[str, str] = None):
        """Increment a counter metric."""
        with self.lock:
            key = self._make_key(name, labels)
            self.counters[key] += value

    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Set a gauge metric."""
        with self.lock:
            key = self._make_key(name, labels)
            self.gauges[key] = value

    def observe_histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Observe a value for histogram metric."""
        with self.lock:
            key = self._make_key(name, labels)
            self.histograms[key].append(value)

            # Keep only last 1000 values
            if len(self.histograms[key]) > 1000:
                self.histograms[key] = self.histograms[key][-1000:]

    def get_metrics(self) -> Dict[str, Any]:
        """Get all metrics."""
        with self.lock:
            metrics = {
                'counters': dict(self.counters),
                'gauges': dict(self.gauges),
                'histograms': {}
            }

            # Calculate histogram statistics
            for key, values in self.histograms.items():
                if values:
                    metrics['histograms'][key] = {
                        'count': len(values),
                        'sum': sum(values),
                        'min': min(values),
                        'max': max(values),
                        'avg': sum(values) / len(values),
                        'p50': self._percentile(values, 0.5),
                        'p95': self._percentile(values, 0.95),
                        'p99': self._percentile(values, 0.99),
                    }

            return metrics

    def reset(self):
        """Reset all metrics."""
        with self.lock:
            self.counters.clear()
            self.gauges.clear()
            self.histograms.clear()

    @staticmethod
    def _make_key(name: str, labels: Optional[Dict[str, str]]) -> str:
        """Create metric key with labels."""
        if not labels:
            return name

        label_str = ','.join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    @staticmethod
    def _percentile(values: List[float], p: float) -> float:
        """Calculate percentile."""
        sorted_values = sorted(values)
        index = int(len(sorted_values) * p)
        return sorted_values[min(index, len(sorted_values) - 1)]


class SystemMonitor:
    """Monitor system resources."""

    @staticmethod
    def get_system_metrics() -> Dict[str, Any]:
        """Get system resource metrics."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            process = psutil.Process(os.getpid())

            return {
                'cpu': {
                    'usage_percent': cpu_percent,
                    'count': psutil.cpu_count(),
                },
                'memory': {
                    'total_mb': memory.total / 1024 / 1024,
                    'available_mb': memory.available / 1024 / 1024,
                    'used_mb': memory.used / 1024 / 1024,
                    'percent': memory.percent,
                    'process_rss_mb': process.memory_info().rss / 1024 / 1024,
                },
                'disk': {
                    'total_gb': disk.total / 1024 / 1024 / 1024,
                    'used_gb': disk.used / 1024 / 1024 / 1024,
                    'free_gb': disk.free / 1024 / 1024 / 1024,
                    'percent': disk.percent,
                },
                'process': {
                    'pid': process.pid,
                    'num_threads': process.num_threads(),
                    'cpu_percent': process.cpu_percent(interval=0.1),
                }
            }
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")
            return {}


class HealthCheck:
    """Health check for service."""

    def __init__(self):
        self.checks: Dict[str, callable] = {}
        self.last_results: Dict[str, bool] = {}

    def register_check(self, name: str, check_func: callable):
        """Register a health check."""
        self.checks[name] = check_func

    def run_checks(self) -> Dict[str, Any]:
        """Run all health checks."""
        results = {}
        all_healthy = True

        for name, check_func in self.checks.items():
            try:
                is_healthy = check_func()
                results[name] = {
                    'status': 'healthy' if is_healthy else 'unhealthy',
                    'timestamp': time.time()
                }
                self.last_results[name] = is_healthy

                if not is_healthy:
                    all_healthy = False

            except Exception as e:
                logger.error(f"Health check failed: {name} - {e}")
                results[name] = {
                    'status': 'error',
                    'error': str(e),
                    'timestamp': time.time()
                }
                all_healthy = False

        return {
            'overall_status': 'healthy' if all_healthy else 'unhealthy',
            'checks': results,
            'timestamp': time.time()
        }

    def is_healthy(self) -> bool:
        """Check if service is overall healthy."""
        return all(self.last_results.values())


# Global instances
metrics_collector = MetricsCollector()
system_monitor = SystemMonitor()
health_check = HealthCheck()


# Decorator for timing functions
def timed(metric_name: str):
    """Decorator to time function execution."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start
                metrics_collector.observe_histogram(
                    f"{metric_name}_duration_seconds",
                    duration
                )
                metrics_collector.increment_counter(
                    f"{metric_name}_total",
                    labels={'status': 'success'}
                )
                return result
            except Exception as e:
                duration = time.time() - start
                metrics_collector.observe_histogram(
                    f"{metric_name}_duration_seconds",
                    duration
                )
                metrics_collector.increment_counter(
                    f"{metric_name}_total",
                    labels={'status': 'error'}
                )
                raise

        return wrapper
    return decorator


# Example health checks
def check_cache() -> bool:
    """Check if cache is accessible."""
    try:
        from cache.ast_cache import ASTCache
        cache = ASTCache()
        # Try to perform a simple operation
        cache.stats()
        return True
    except:
        return False


def check_database() -> bool:
    """Check if database is accessible."""
    try:
        from db.connection import get_session
        with get_session() as session:
            # Simple query to check connection
            session.execute("SELECT 1")
        return True
    except:
        return False


# Register default health checks
health_check.register_check('cache', check_cache)
health_check.register_check('database', check_database)
