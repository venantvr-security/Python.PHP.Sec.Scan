"""Mock exporters for BDD tests."""

class MockSARIFExporter:
    """Mock SARIF exporter."""

    @staticmethod
    def export(results):
        """Export to SARIF format."""
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "PHP Security Scanner",
                        "version": "2.3.0"
                    }
                },
                "results": [
                    {
                        "ruleId": vuln['type'],
                        "level": vuln.get('severity', 'warning'),
                        "message": {
                            "text": vuln.get('message', 'Security vulnerability detected')
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": vuln['file']
                                },
                                "region": {
                                    "startLine": vuln.get('line', 1)
                                }
                            }
                        }]
                    }
                    for vuln in results if isinstance(vuln, dict)
                ]
            }]
        }

class MockHTMLExporter:
    """Mock HTML exporter."""

    @staticmethod
    def export(results):
        """Export to HTML format."""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>PHP Security Scanner Report</title>
</head>
<body>
    <h1>Security Scan Report</h1>
    <table>
        <tr>
            <th>Type</th>
            <th>Severity</th>
            <th>File</th>
            <th>Line</th>
        </tr>
"""
        for vuln in results:
            if isinstance(vuln, dict):
                html += f"""        <tr>
            <td>{vuln['type']}</td>
            <td>{vuln.get('severity', 'unknown')}</td>
            <td>{vuln['file']}</td>
            <td>{vuln.get('line', 'N/A')}</td>
        </tr>
"""
        html += """    </table>
</body>
</html>"""
        return html

class MockJSONExporter:
    """Mock JSON exporter."""

    @staticmethod
    def export(results):
        """Export to JSON format."""
        import json
        return json.dumps({
            "scan_results": results,
            "total_vulnerabilities": len(results),
            "summary": {
                vuln['type']: sum(1 for v in results if v.get('type') == vuln['type'])
                for vuln in results if isinstance(vuln, dict)
            }
        }, indent=2)
