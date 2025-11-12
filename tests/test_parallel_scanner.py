# tests/test_parallel_scanner.py
"""Tests for parallel scanner, caching, and database integration."""
import os
import tempfile
from pathlib import Path

import pytest

from workers.parallel_scanner import ParallelScanner
from cache.ast_cache import ASTCache
from db.connection import get_session, init_db
from db.models import Project, Scan, Vulnerability


def test_parallel_scanner_basic():
    """Test basic parallel scanning."""
    scanner = ParallelScanner(
        vuln_types=['sql_injection', 'xss'],
        max_workers=4,
        use_cache=False,
        verbose=False
    )

    # Scan test files
    test_dir = Path('tests/vuln_samples')
    if test_dir.exists():
        results = scanner.scan_directory(str(test_dir))

        assert len(results) > 0
        assert all('vulnerabilities' in r for r in results.values())
        assert all('warnings' in r for r in results.values())

        stats = scanner.get_statistics(results)
        assert stats['total_files'] > 0
        assert 'total_vulnerabilities' in stats
        assert 'cache_hit_rate' in stats


def test_cache_functionality():
    """Test AST cache."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache = ASTCache(cache_dir=tmpdir, ttl=60)

        # Set and get
        test_data = {
            'vulnerabilities': [{'type': 'xss', 'line': 10}],
            'warnings': []
        }

        cache.set('test_key', test_data)
        retrieved = cache.get('test_key')

        assert retrieved is not None
        assert retrieved['vulnerabilities'] == test_data['vulnerabilities']

        # Test cache stats
        stats = cache.stats()
        assert 'size' in stats
        assert stats['size'] >= 1

        # Test delete
        cache.delete('test_key')
        assert cache.get('test_key') is None

        cache.close()


def test_parallel_scanner_with_cache():
    """Test parallel scanner with caching enabled."""
    with tempfile.TemporaryDirectory() as cache_dir:
        os.environ['CACHE_DIR'] = cache_dir

        scanner = ParallelScanner(
            vuln_types=['sql_injection'],
            max_workers=2,
            use_cache=True,
            verbose=False
        )

        test_dir = Path('tests/vuln_samples')
        if not test_dir.exists():
            pytest.skip("Test directory not found")

        # First scan (no cache)
        results1 = scanner.scan_directory(str(test_dir))
        stats1 = scanner.get_statistics(results1)

        # Second scan (should hit cache)
        results2 = scanner.scan_directory(str(test_dir))
        stats2 = scanner.get_statistics(results2)

        # Cache should be used
        assert stats2['cache_hit_rate'] > 0.5  # At least 50% cache hits

        # Results should be consistent
        assert len(results1) == len(results2)


def test_database_integration():
    """Test database models and storage."""
    # Create unique in-memory database for this test
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from db.models import Base

    test_engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(bind=test_engine)
    TestSession = sessionmaker(bind=test_engine)

    session = TestSession()
    try:
        # Create project
        project = Project(
            name='test_project',
            root_path='/test/path',
            is_wordpress=False
        )
        session.add(project)
        session.flush()

        # Create scan
        scan = Scan(
            project_id=project.id,
            vuln_types=['xss', 'sql_injection'],
            total_files=10,
            total_vulnerabilities=2,
            scanned_files=10
        )
        session.add(scan)
        session.flush()

        # Create vulnerability
        vuln = Vulnerability(
            scan_id=scan.id,
            vuln_type='xss',
            filepath='/test/file.php',
            line_number=42,
            sink_function='echo',
            tainted_variable='$input'
        )
        session.add(vuln)
        session.commit()

        # Query back
        retrieved_project = session.query(Project).filter_by(name='test_project').first()
        assert retrieved_project is not None
        assert retrieved_project.name == 'test_project'

        retrieved_scan = session.query(Scan).filter_by(project_id=project.id).first()
        assert retrieved_scan is not None
        assert retrieved_scan.total_vulnerabilities == 2

        retrieved_vulns = session.query(Vulnerability).filter_by(scan_id=scan.id).all()
        assert len(retrieved_vulns) == 1
        assert retrieved_vulns[0].vuln_type == 'xss'
    finally:
        session.close()


def test_parallel_scanner_statistics():
    """Test statistics computation."""
    scanner = ParallelScanner(
        vuln_types=['sql_injection', 'xss'],
        max_workers=2,
        use_cache=False
    )

    # Mock results
    results = {
        'file1.php': {
            'vulnerabilities': [
                {'type': 'sql_injection', 'line': 10},
                {'type': 'xss', 'line': 20}
            ],
            'warnings': [],
            'analysis_time': 0.5,
            'cached': False
        },
        'file2.php': {
            'vulnerabilities': [],
            'warnings': [{'type': 'unsanitized_source'}],
            'analysis_time': 0.3,
            'cached': True
        }
    }

    stats = scanner.get_statistics(results)

    assert stats['total_files'] == 2
    assert stats['total_vulnerabilities'] == 2
    assert stats['total_warnings'] == 1
    assert stats['cache_hits'] == 1
    assert stats['cache_hit_rate'] == 0.5
    assert stats['total_analysis_time'] == 0.8
    assert stats['average_time_per_file'] == 0.4
    assert 'sql_injection' in stats['vulnerabilities_by_type']
    assert stats['vulnerabilities_by_type']['sql_injection'] == 1
    assert stats['vulnerabilities_by_type']['xss'] == 1


def test_parallel_scanner_error_handling():
    """Test error handling in parallel scanner."""
    scanner = ParallelScanner(
        vuln_types=['sql_injection'],
        max_workers=2,
        use_cache=False
    )

    # Try to scan non-existent files
    results = scanner.scan_files(['non_existent_file.php'])

    assert 'non_existent_file.php' in results
    assert 'error' in results['non_existent_file.php']

    stats = scanner.get_statistics(results)
    assert stats['errors'] == 1
