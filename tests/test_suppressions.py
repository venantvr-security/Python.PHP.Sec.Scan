# tests/test_suppressions.py
import tempfile
import os
from suppressions.manager import SuppressionManager, AllowlistManager


def test_suppression_basic():
    """Test basic suppression functionality."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        temp_path = f.name

    try:
        manager = SuppressionManager(temp_path)

        vuln = {
            'type': 'xss',
            'file': '/project/index.php',
            'line': 10,
            'sink': 'echo'
        }

        # Should not be suppressed initially
        assert not manager.is_suppressed(vuln)

        # Add suppression
        manager.add_suppression(vuln, reason="False positive", author="test_user")

        # Should now be suppressed
        assert manager.is_suppressed(vuln)

        # Different vuln should not be suppressed
        vuln2 = {
            'type': 'xss',
            'file': '/project/index.php',
            'line': 20,
            'sink': 'echo'
        }
        assert not manager.is_suppressed(vuln2)

    finally:
        os.unlink(temp_path)


def test_suppression_filter():
    """Test filtering vulnerabilities."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        temp_path = f.name

    try:
        manager = SuppressionManager(temp_path)

        vulns = [
            {'type': 'xss', 'file': 'test.php', 'line': 10, 'sink': 'echo'},
            {'type': 'sql_injection', 'file': 'test.php', 'line': 20, 'sink': 'query'},
            {'type': 'rce', 'file': 'test.php', 'line': 30, 'sink': 'eval'},
        ]

        # Suppress first vulnerability
        manager.add_suppression(vulns[0], reason="Test suppression")

        active, suppressed = manager.filter_vulnerabilities(vulns)

        assert len(active) == 2
        assert len(suppressed) == 1
        assert suppressed[0]['type'] == 'xss'

    finally:
        os.unlink(temp_path)


def test_suppression_pattern():
    """Test pattern-based suppression."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        temp_path = f.name

    try:
        manager = SuppressionManager(temp_path)

        # Add pattern suppression for all XSS in test files
        manager.add_pattern_suppression(
            pattern={'file': 'test.php', 'type': 'xss'},
            reason="Test files are safe"
        )

        vuln1 = {'type': 'xss', 'file': '/project/test.php', 'line': 10, 'sink': 'echo'}
        vuln2 = {'type': 'xss', 'file': '/project/prod.php', 'line': 10, 'sink': 'echo'}
        vuln3 = {'type': 'sql_injection', 'file': '/project/test.php', 'line': 20, 'sink': 'query'}

        assert manager.is_suppressed(vuln1)  # Matches pattern
        assert not manager.is_suppressed(vuln2)  # Different file
        assert not manager.is_suppressed(vuln3)  # Different type

    finally:
        os.unlink(temp_path)


def test_suppression_statistics():
    """Test suppression statistics."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        temp_path = f.name

    try:
        manager = SuppressionManager(temp_path)

        vulns = [
            {'type': 'xss', 'file': 'test.php', 'line': 10, 'sink': 'echo'},
            {'type': 'xss', 'file': 'test.php', 'line': 20, 'sink': 'echo'},
            {'type': 'sql_injection', 'file': 'test.php', 'line': 30, 'sink': 'query'},
        ]

        for vuln in vulns:
            manager.add_suppression(vuln, reason="Test", author="user1")

        stats = manager.get_statistics()

        assert stats['total_suppressions'] == 3
        assert stats['by_type']['xss'] == 2
        assert stats['by_type']['sql_injection'] == 1
        assert stats['by_author']['user1'] == 3

    finally:
        os.unlink(temp_path)


def test_allowlist_basic():
    """Test basic allowlist functionality."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        temp_path = f.name

    try:
        manager = AllowlistManager(temp_path)

        # Add pattern to allowlist
        manager.add_pattern(
            pattern={'file_pattern': r'vendor/.*', 'type': 'xss'},
            reason="Third-party code"
        )

        vuln1 = {'type': 'xss', 'file': '/project/vendor/lib/test.php', 'line': 10}
        vuln2 = {'type': 'xss', 'file': '/project/src/app.php', 'line': 20}

        assert manager.is_allowed(vuln1)  # In vendor directory
        assert not manager.is_allowed(vuln2)  # Not in vendor

    finally:
        os.unlink(temp_path)


def test_suppression_persistence():
    """Test that suppressions persist across instances."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        temp_path = f.name

    try:
        # Create first manager and add suppression
        manager1 = SuppressionManager(temp_path)
        vuln = {'type': 'xss', 'file': 'test.php', 'line': 10, 'sink': 'echo'}
        manager1.add_suppression(vuln, reason="Test")

        # Create new manager instance and check suppression persists
        manager2 = SuppressionManager(temp_path)
        assert manager2.is_suppressed(vuln)
        assert len(manager2.suppressions) == 1

    finally:
        os.unlink(temp_path)
