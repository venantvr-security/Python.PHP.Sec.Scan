#!/usr/bin/env python3
"""
Full-stack integration tests.

Tests the entire scanner pipeline from end to end:
- File scanning
- Database storage
- SARIF export
- Suppression system
- Plugin integration
- API endpoints
"""

import tempfile
import os
import json
from pathlib import Path
import pytest

from workers.parallel_scanner import ParallelScanner
from db.connection import get_session, init_db, create_engine
from db.models import Project, Scan, Vulnerability, Base
from exporters.sarif import SARIFExporter
from suppressions.manager import SuppressionManager
from plugins import PluginManager, WordPressPlugin, PerformancePlugin


@pytest.fixture
def test_db():
    """Create test database."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine)

    yield TestSession

    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def test_php_files():
    """Create test PHP files."""
    tmpdir = tempfile.mkdtemp()

    # Vulnerable file
    vuln_file = os.path.join(tmpdir, 'vulnerable.php')
    with open(vuln_file, 'w') as f:
        f.write('''<?php
$id = $_GET['id'];
echo $id;  // XSS
$result = query("SELECT * FROM users WHERE id = " . $id);  // SQL injection
eval($_POST['code']);  // RCE
?>''')

    # Safe file
    safe_file = os.path.join(tmpdir, 'safe.php')
    with open(safe_file, 'w') as f:
        f.write('''<?php
function sanitize($input) {
    return htmlspecialchars($input);
}

$id = sanitize($_GET['id']);
echo $id;
?>''')

    # WordPress file
    wp_file = os.path.join(tmpdir, 'wordpress.php')
    with open(wp_file, 'w') as f:
        f.write('''<?php
add_action('init', 'my_function');

function my_function() {
    $data = $_GET['data'];
    echo $data;  // Missing esc_html
}
?>''')

    yield [vuln_file, safe_file, wp_file], tmpdir

    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_end_to_end_scan(test_php_files):
    """Test complete scan workflow."""
    files, tmpdir = test_php_files

    # Create scanner
    scanner = ParallelScanner(
        vuln_types=['sql_injection', 'xss', 'rce'],
        max_workers=2,
        use_cache=True,
        verbose=False
    )

    # Scan files
    results = scanner.scan_files(files)

    # Verify results
    assert len(results) == 3

    # Count vulnerabilities
    all_vulns = []
    for file_result in results.values():
        all_vulns.extend(file_result.get('vulnerabilities', []))

    assert len(all_vulns) >= 2  # At least XSS

    # Verify types
    types = {v['type'] for v in all_vulns}
    assert 'xss' in types


def test_database_integration(test_php_files, test_db):
    """Test database storage."""
    files, tmpdir = test_php_files

    # Scan
    scanner = ParallelScanner(
        vuln_types=['xss', 'sql_injection'],
        max_workers=2,
        use_cache=False
    )

    results = scanner.scan_files(files)

    # Save to database
    session = test_db()

    project = Project(
        name='test_project',
        root_path=tmpdir,
    )
    session.add(project)
    session.flush()

    from db.models import ScanStatus
    scan = Scan(
        project_id=project.id,
        vuln_types='xss,sql_injection',
        status=ScanStatus.COMPLETED,
        total_files=len(files),
        scanned_files=len(files),
    )
    session.add(scan)
    session.flush()

    # Add vulnerabilities
    from db.models import VulnerabilitySeverity
    for file_result in results.values():
        for vuln in file_result.get('vulnerabilities', []):
            severity = vuln.get('severity', 'medium').upper()
            try:
                severity_enum = VulnerabilitySeverity[severity]
            except KeyError:
                severity_enum = VulnerabilitySeverity.MEDIUM

            vuln_obj = Vulnerability(
                scan_id=scan.id,
                vuln_type=vuln['type'],
                filepath=vuln['file'],
                line_number=vuln['line'],
                severity=severity_enum,
            )
            session.add(vuln_obj)

    session.commit()

    # Query back
    stored_vulns = session.query(Vulnerability).filter_by(scan_id=scan.id).all()
    assert len(stored_vulns) > 0

    session.close()


def test_sarif_export(test_php_files):
    """Test SARIF export."""
    files, tmpdir = test_php_files

    # Scan
    scanner = ParallelScanner(
        vuln_types=['xss', 'sql_injection', 'rce'],
        max_workers=2
    )

    results = scanner.scan_files(files)

    # Collect vulnerabilities
    all_vulns = []
    for file_result in results.values():
        all_vulns.extend(file_result.get('vulnerabilities', []))

    # Export SARIF
    exporter = SARIFExporter()
    sarif = exporter.export(all_vulns, tmpdir)

    # Verify SARIF structure
    assert sarif['version'] == '2.1.0'
    assert 'runs' in sarif
    assert len(sarif['runs']) == 1

    run = sarif['runs'][0]
    assert 'tool' in run
    assert 'results' in run
    assert len(run['results']) == len(all_vulns)

    # Test file export
    sarif_file = os.path.join(tmpdir, 'results.sarif')
    exporter.export_to_file(all_vulns, sarif_file)

    assert os.path.exists(sarif_file)

    with open(sarif_file) as f:
        loaded_sarif = json.load(f)

    assert loaded_sarif['version'] == '2.1.0'


def test_suppression_integration(test_php_files):
    """Test suppression system."""
    files, tmpdir = test_php_files

    # Scan
    scanner = ParallelScanner(
        vuln_types=['xss', 'sql_injection'],
        max_workers=2
    )

    results = scanner.scan_files(files)

    # Collect vulnerabilities
    all_vulns = []
    for file_result in results.values():
        all_vulns.extend(file_result.get('vulnerabilities', []))

    original_count = len(all_vulns)

    # Create suppression manager
    suppression_file = os.path.join(tmpdir, 'suppressions.yaml')
    manager = SuppressionManager(suppression_file)

    # Suppress first vulnerability
    if all_vulns:
        manager.add_suppression(all_vulns[0], reason="Test suppression", author="test")

    # Filter vulnerabilities
    active, suppressed = manager.filter_vulnerabilities(all_vulns)

    assert len(suppressed) == 1
    assert len(active) == original_count - 1


def test_plugin_integration(test_php_files):
    """Test plugin system integration."""
    files, tmpdir = test_php_files

    # Create WordPress indicator
    wp_config = os.path.join(tmpdir, 'wp-config.php')
    with open(wp_config, 'w') as f:
        f.write('<?php // WordPress config ?>')

    # Initialize plugin manager
    plugin_manager = PluginManager()
    wp_plugin = WordPressPlugin()
    perf_plugin = PerformancePlugin()

    plugin_manager.register(wp_plugin)
    plugin_manager.register(perf_plugin)

    # Create scanner with plugins
    scanner = ParallelScanner(
        vuln_types=['xss'],
        max_workers=2,
        plugin_manager=plugin_manager
    )

    # Scan with context
    scan_context = {'root_path': tmpdir, 'project': 'test'}
    results = scanner.scan_files(files, scan_context=scan_context)

    # Verify WordPress detection
    assert scan_context.get('is_wordpress') is True

    # Verify plugins were called
    assert perf_plugin.start_time is not None


def test_full_pipeline_with_all_features(test_php_files, test_db):
    """Test complete pipeline with all features enabled."""
    files, tmpdir = test_php_files

    # Setup
    suppression_file = os.path.join(tmpdir, 'suppressions.yaml')
    suppression_manager = SuppressionManager(suppression_file)

    plugin_manager = PluginManager()
    plugin_manager.register(PerformancePlugin())

    scanner = ParallelScanner(
        vuln_types=['xss', 'sql_injection', 'rce'],
        max_workers=4,
        use_cache=True,
        plugin_manager=plugin_manager
    )

    # Scan
    scan_context = {'root_path': tmpdir, 'project': 'full_test'}
    results = scanner.scan_files(files, scan_context=scan_context)

    # Get statistics
    stats = scanner.get_statistics(results)

    assert stats['total_files'] == 3
    assert stats['total_vulnerabilities'] > 0

    # Collect vulnerabilities
    all_vulns = []
    for file_result in results.values():
        all_vulns.extend(file_result.get('vulnerabilities', []))

    # Apply suppressions
    active_vulns, suppressed_vulns = suppression_manager.filter_vulnerabilities(all_vulns)

    # Export SARIF
    exporter = SARIFExporter()
    sarif_file = os.path.join(tmpdir, 'full_test.sarif')
    exporter.export_to_file(active_vulns, sarif_file)

    assert os.path.exists(sarif_file)

    # Save to database
    session = test_db()

    project = Project(name='full_test', root_path=tmpdir)
    session.add(project)
    session.flush()

    from db.models import ScanStatus
    scan = Scan(
        project_id=project.id,
        vuln_types='xss,sql_injection,rce',
        status=ScanStatus.COMPLETED,
        scanned_files=len(files),
        total_vulnerabilities=len(active_vulns),
    )
    session.add(scan)
    session.commit()

    # Verify everything worked
    assert scan.id is not None
    assert os.path.exists(sarif_file)
    assert len(active_vulns) > 0

    session.close()


def test_cli_integration(test_php_files):
    """Test CLI integration."""
    import subprocess
    import sys

    files, tmpdir = test_php_files

    output_file = os.path.join(tmpdir, 'cli_results.json')

    # Run CLI (updated command structure)
    result = subprocess.run([
        sys.executable, 'cli.py', 'scan',
        '--files'] + files + [
        '--output', output_file,
        '--no-db',
        '--no-progress',
        '--workers', '2',
    ], capture_output=True, text=True)

    # Check output file was created
    assert os.path.exists(output_file)

    with open(output_file) as f:
        data = json.load(f)

    assert 'statistics' in data
    assert 'results' in data
    assert data['statistics']['total_files'] == 3


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
