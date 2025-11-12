# tests/test_sarif.py
import json
import os
import tempfile

from exporters.sarif import SARIFExporter


def test_sarif_basic_export():
    """Test basic SARIF export."""
    exporter = SARIFExporter()

    vulns = [
        {
            'type': 'xss',
            'file': '/project/index.php',
            'line': 10,
            'column': 5,
            'severity': 'high',
            'sink': 'echo'
        }
    ]

    sarif = exporter.export(vulns, project_root='/project')

    assert sarif['version'] == '2.1.0'
    assert len(sarif['runs']) == 1
    assert len(sarif['runs'][0]['results']) == 1

    result = sarif['runs'][0]['results'][0]
    assert result['ruleId'] == 'xss'
    assert result['level'] == 'error'
    assert result['locations'][0]['physicalLocation']['artifactLocation']['uri'] == 'index.php'
    assert result['locations'][0]['physicalLocation']['region']['startLine'] == 10


def test_sarif_multiple_vulnerabilities():
    """Test SARIF export with multiple vulnerabilities."""
    exporter = SARIFExporter()

    vulns = [
        {'type': 'sql_injection', 'file': 'test.php', 'line': 5, 'severity': 'critical', 'sink': 'query'},
        {'type': 'xss', 'file': 'test.php', 'line': 10, 'severity': 'high', 'sink': 'echo'},
        {'type': 'rce', 'file': 'admin.php', 'line': 20, 'severity': 'critical', 'sink': 'eval'},
    ]

    sarif = exporter.export(vulns)

    assert len(sarif['runs'][0]['results']) == 3
    assert len(sarif['runs'][0]['tool']['driver']['rules']) == 3

    # Check rules were generated
    rule_ids = [r['id'] for r in sarif['runs'][0]['tool']['driver']['rules']]
    assert 'sql_injection' in rule_ids
    assert 'xss' in rule_ids
    assert 'rce' in rule_ids


def test_sarif_interprocedural():
    """Test SARIF export with inter-procedural vulnerability."""
    exporter = SARIFExporter()

    vulns = [
        {
            'type': 'rce',
            'file': 'functions.php',
            'line': 50,
            'severity': 'critical',
            'sink': 'system',
            'interprocedural': True,
            'call_chain': [
                {'file': 'index.php', 'line': 10, 'function': 'processInput'},
                {'file': 'functions.php', 'line': 50, 'function': 'executeCommand'}
            ]
        }
    ]

    sarif = exporter.export(vulns)
    result = sarif['runs'][0]['results'][0]

    assert 'codeFlows' in result
    assert len(result['codeFlows'][0]['threadFlows'][0]['locations']) == 2


def test_sarif_file_export():
    """Test SARIF export to file."""
    exporter = SARIFExporter()

    vulns = [
        {'type': 'xss', 'file': 'test.php', 'line': 5, 'severity': 'medium', 'sink': 'echo'}
    ]

    with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False) as f:
        temp_path = f.name

    try:
        exporter.export_to_file(vulns, temp_path)

        with open(temp_path, 'r') as f:
            sarif = json.load(f)

        assert sarif['version'] == '2.1.0'
        assert len(sarif['runs'][0]['results']) == 1
    finally:
        os.unlink(temp_path)


def test_sarif_wordpress_rules():
    """Test SARIF export with WordPress vulnerabilities."""
    exporter = SARIFExporter()

    vulns = [
        {'type': 'wp_xss', 'file': 'plugin.php', 'line': 100, 'severity': 'high', 'sink': 'echo'},
        {'type': 'wp_sql_injection', 'file': 'plugin.php', 'line': 200, 'severity': 'critical', 'sink': 'query'},
    ]

    sarif = exporter.export(vulns)
    rules = sarif['runs'][0]['tool']['driver']['rules']

    assert len(rules) == 2
    wp_rule = [r for r in rules if r['id'] == 'wp_xss'][0]
    assert 'wordpress' in wp_rule['properties']['tags']
