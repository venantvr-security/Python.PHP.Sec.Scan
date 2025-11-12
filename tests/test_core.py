"""Tests for core modules."""

import pytest
from pathlib import Path
import tempfile
import os

from core.exceptions import ValidationError, ConfigurationError
from core.validators import validate_file_path, validate_directory, validate_vulnerability_types
from core.config import Config, ScanConfig, load_config
from core.rate_limiter import TokenBucket, SlidingWindowRateLimiter, RateLimiter
from core.detection_engine import DetectionEngine, Severity, Confidence


class TestValidators:
    """Test input validators."""

    def test_validate_file_path_exists(self, tmp_path):
        """Test validating existing file."""
        test_file = tmp_path / "test.php"
        test_file.write_text("<?php echo 'test'; ?>")

        result = validate_file_path(str(test_file))
        assert result.is_file()

    def test_validate_file_path_not_exists(self):
        """Test validating non-existent file."""
        with pytest.raises(ValidationError, match="does not exist"):
            validate_file_path("/nonexistent/file.php", must_exist=True)

    def test_validate_directory_exists(self, tmp_path):
        """Test validating existing directory."""
        result = validate_directory(str(tmp_path))
        assert result.is_dir()

    def test_validate_directory_not_exists(self):
        """Test validating non-existent directory."""
        with pytest.raises(ValidationError, match="does not exist"):
            validate_directory("/nonexistent/dir", must_exist=True)

    def test_validate_vulnerability_types_valid(self):
        """Test validating valid vulnerability types."""
        types = ['sql_injection', 'xss', 'rce']
        result = validate_vulnerability_types(types)
        assert result == types

    def test_validate_vulnerability_types_invalid(self):
        """Test validating invalid vulnerability types."""
        with pytest.raises(ValidationError, match="Invalid vulnerability types"):
            validate_vulnerability_types(['invalid_type'])

    def test_validate_vulnerability_types_empty(self):
        """Test validating empty list."""
        with pytest.raises(ValidationError, match="At least one"):
            validate_vulnerability_types([])


class TestConfig:
    """Test configuration management."""

    def test_config_defaults(self):
        """Test default configuration."""
        config = Config()
        assert config.scan.max_file_size > 0
        assert config.cache.enabled
        assert config.performance.max_workers > 0

    def test_config_from_dict(self):
        """Test creating config from dict."""
        data = {
            'scan': {'max_file_size': 5000000},
            'performance': {'max_workers': 16}
        }
        config = Config.from_dict(data)
        assert config.scan.max_file_size == 5000000
        assert config.performance.max_workers == 16

    def test_config_validation_invalid_file_size(self):
        """Test config validation with invalid file size."""
        config = Config()
        config.scan.max_file_size = -1

        with pytest.raises(ConfigurationError, match="must be positive"):
            config.validate()

    def test_config_validation_invalid_workers(self):
        """Test config validation with invalid workers."""
        config = Config()
        config.performance.max_workers = 0

        with pytest.raises(ConfigurationError, match="must be positive"):
            config.validate()


class TestRateLimiter:
    """Test rate limiting."""

    def test_token_bucket_consume(self):
        """Test token bucket consumption."""
        bucket = TokenBucket(capacity=10, refill_rate=5.0)

        # Should succeed
        assert bucket.consume(5)

        # Should succeed
        assert bucket.consume(5)

        # Should fail (no tokens left)
        assert not bucket.consume(1)

    def test_token_bucket_refill(self):
        """Test token bucket refill."""
        import time

        bucket = TokenBucket(capacity=10, refill_rate=10.0)
        bucket.consume(10)

        # Wait for refill
        time.sleep(0.5)

        # Should have ~5 tokens now
        assert bucket.consume(4)

    def test_sliding_window_rate_limiter(self):
        """Test sliding window rate limiter."""
        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=1)

        # First 5 requests should succeed
        for i in range(5):
            assert limiter.is_allowed('test_key')

        # 6th request should fail
        assert not limiter.is_allowed('test_key')

    def test_sliding_window_different_keys(self):
        """Test sliding window with different keys."""
        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=1)

        assert limiter.is_allowed('key1')
        assert limiter.is_allowed('key2')
        assert limiter.is_allowed('key1')

        # key1 should be limited now
        assert not limiter.is_allowed('key1')

        # key2 still has capacity
        assert limiter.is_allowed('key2')


class TestDetectionEngine:
    """Test detection engine."""

    def test_get_rule_existing(self):
        """Test getting existing rule."""
        rule = DetectionEngine.get_rule('sql_injection')
        assert rule is not None
        assert rule.vuln_type == 'sql_injection'
        assert rule.severity == Severity.CRITICAL

    def test_get_rule_nonexistent(self):
        """Test getting non-existent rule."""
        rule = DetectionEngine.get_rule('nonexistent')
        assert rule is None

    def test_get_severity(self):
        """Test getting severity."""
        severity = DetectionEngine.get_severity('rce')
        assert severity == Severity.CRITICAL

    def test_get_cwe_id(self):
        """Test getting CWE ID."""
        cwe_id = DetectionEngine.get_cwe_id('sql_injection')
        assert cwe_id == 89

    def test_calculate_confidence_high(self):
        """Test confidence calculation - high."""
        confidence = DetectionEngine.calculate_confidence(
            has_sanitization=False,
            has_validation=False,
            context_analysis=True
        )
        assert confidence == Confidence.HIGH

    def test_calculate_confidence_low(self):
        """Test confidence calculation - low."""
        confidence = DetectionEngine.calculate_confidence(
            has_sanitization=True,
            has_validation=False,
            context_analysis=False
        )
        assert confidence == Confidence.LOW

    def test_all_rules_have_required_fields(self):
        """Test that all rules have required fields."""
        for vuln_type, rule in DetectionEngine.get_all_rules().items():
            assert rule.id
            assert rule.name
            assert rule.vuln_type == vuln_type
            assert rule.severity
            assert rule.description
            assert rule.sources is not None
            assert rule.sinks is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
