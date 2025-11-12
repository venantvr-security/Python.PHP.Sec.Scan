# tests/test_plugins.py
import tempfile
import os
from plugins import (
    PluginManager, ScannerPlugin, WordPressPlugin,
    PerformancePlugin, NotificationPlugin
)
from plugins.custom_rules import CustomRulesPlugin
from plugins.metrics_exporter import MetricsExporterPlugin
from plugins.security_policy import SecurityPolicyPlugin


def test_plugin_manager_basic():
    """Test plugin manager registration."""
    manager = PluginManager()

    plugin = WordPressPlugin()
    manager.register(plugin)

    assert len(manager.plugins) == 1
    assert manager.plugins[0].name == "WordPress Security Plugin"


def test_plugin_manager_multiple():
    """Test multiple plugin registration."""
    manager = PluginManager()

    manager.register(WordPressPlugin())
    manager.register(PerformancePlugin())

    assert len(manager.plugins) == 2


def test_wordpress_plugin_detection():
    """Test WordPress detection."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create fake WordPress files
        open(os.path.join(tmpdir, 'wp-config.php'), 'w').close()

        plugin = WordPressPlugin()
        scan_context = {'root_path': tmpdir}

        plugin.on_scan_start(scan_context)

        assert scan_context['is_wordpress'] is True


def test_performance_plugin_timing():
    """Test performance tracking."""
    plugin = PerformancePlugin()

    scan_context = {}
    plugin.on_scan_start(scan_context)

    assert plugin.start_time is not None

    # Simulate file scan
    plugin.on_file_scanned('/test/file.php', {'scan_time': 0.123})

    assert len(plugin.file_times) == 1
    assert plugin.file_times[0][1] == 0.123


def test_notification_plugin_no_webhook():
    """Test notification plugin without webhook."""
    plugin = NotificationPlugin()

    # Should not crash without webhook
    plugin.on_scan_complete({
        'project': 'test',
        'vulnerabilities': []
    })


def test_custom_rules_plugin():
    """Test custom rules detection."""
    plugin = CustomRulesPlugin()

    scan_context = {}
    plugin.on_scan_start(scan_context)

    # Create temp file with dangerous function
    with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as f:
        f.write('<?php mysql_query($sql); ?>')
        temp_path = f.name

    try:
        results = {}
        plugin.on_file_scanned(temp_path, results)

        assert 'custom_warnings' in results
        assert len(results['custom_warnings']) > 0
        assert results['custom_warnings'][0]['function'] == 'mysql_query'

    finally:
        os.unlink(temp_path)


def test_metrics_exporter_json():
    """Test metrics export to JSON."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plugin = MetricsExporterPlugin(export_format='json', output_dir=tmpdir)

        scan_context = {'project': 'test', 'root_path': '/tmp'}
        plugin.on_scan_start(scan_context)

        # Simulate file scans
        plugin.on_file_scanned('/test/file1.php', {
            'vulnerabilities': [
                {'type': 'xss', 'severity': 'high'}
            ]
        })

        plugin.on_file_scanned('/test/file2.php', {
            'vulnerabilities': []
        })

        plugin.on_scan_complete({
            'statistics': {
                'total_files': 2,
                'cache_hit_rate': 0.5,
                'total_analysis_time': 1.23
            }
        })

        # Check JSON file was created
        files = os.listdir(tmpdir)
        assert len(files) == 1
        assert files[0].startswith('metrics_')


def test_metrics_exporter_prometheus():
    """Test metrics export to Prometheus format."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plugin = MetricsExporterPlugin(export_format='prometheus', output_dir=tmpdir)

        scan_context = {'project': 'test', 'root_path': '/tmp'}
        plugin.on_scan_start(scan_context)

        plugin.on_file_scanned('/test/file1.php', {
            'vulnerabilities': [
                {'type': 'sql_injection', 'severity': 'critical'}
            ]
        })

        plugin.on_scan_complete({
            'statistics': {
                'total_files': 1,
                'cache_hit_rate': 1.0,
                'total_analysis_time': 0.5
            }
        })

        # Check Prometheus file was created
        prom_file = os.path.join(tmpdir, 'metrics.prom')
        assert os.path.exists(prom_file)

        with open(prom_file) as f:
            content = f.read()
            assert 'php_scanner_files_total' in content
            assert 'php_scanner_vulnerabilities_total' in content


def test_security_policy_pass():
    """Test security policy enforcement - passing."""
    plugin = SecurityPolicyPlugin(
        max_critical=0,
        max_high=5,
        max_total=10,
        fail_on_violation=False
    )

    scan_context = {}
    plugin.on_scan_start(scan_context)

    # Add vulnerabilities within limits
    plugin.on_file_scanned('/test/file.php', {
        'vulnerabilities': [
            {'severity': 'medium'},
            {'severity': 'low'},
        ]
    })

    # Should not raise
    plugin.on_scan_complete({})

    assert plugin.counts['total'] == 2


def test_security_policy_violation():
    """Test security policy enforcement - violation."""
    plugin = SecurityPolicyPlugin(
        max_critical=0,
        max_high=1,
        fail_on_violation=False  # Don't actually exit in test
    )

    scan_context = {}
    plugin.on_scan_start(scan_context)

    # Add vulnerabilities exceeding limits
    plugin.on_file_scanned('/test/file.php', {
        'vulnerabilities': [
            {'severity': 'high'},
            {'severity': 'high'},
            {'severity': 'high'},
        ]
    })

    # Should detect violation
    plugin.on_scan_complete({})

    assert plugin.counts['high'] > plugin.max_high


def test_vulnerability_processing():
    """Test vulnerability processing through plugin chain."""
    manager = PluginManager()

    class TestPlugin(ScannerPlugin):
        def on_scan_start(self, scan_context):
            pass

        def on_file_scanned(self, file_path, results):
            pass

        def on_scan_complete(self, scan_results):
            pass

        def on_vulnerability_found(self, vulnerability):
            # Modify severity
            if vulnerability['type'] == 'xss':
                vulnerability['severity'] = 'critical'
            return vulnerability

    manager.register(TestPlugin())

    vuln = {'type': 'xss', 'severity': 'low'}
    processed = manager.process_vulnerability(vuln)

    assert processed['severity'] == 'critical'


def test_plugin_filtering():
    """Test plugin can filter out vulnerabilities."""
    manager = PluginManager()

    class FilterPlugin(ScannerPlugin):
        def on_scan_start(self, scan_context):
            pass

        def on_file_scanned(self, file_path, results):
            pass

        def on_scan_complete(self, scan_results):
            pass

        def on_vulnerability_found(self, vulnerability):
            # Filter out low severity
            if vulnerability.get('severity') == 'low':
                return None
            return vulnerability

    manager.register(FilterPlugin())

    vuln_low = {'type': 'xss', 'severity': 'low'}
    vuln_high = {'type': 'xss', 'severity': 'high'}

    assert manager.process_vulnerability(vuln_low) is None
    assert manager.process_vulnerability(vuln_high) is not None
