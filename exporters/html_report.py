# exporters/html_report.py
"""HTML report generator with interactive features."""

import json
from datetime import datetime
from typing import List, Dict


class HTMLReportGenerator:
    """Generate HTML reports for scan results."""

    def __init__(self):
        self.template = self._get_template()

    def generate(self, vulnerabilities: List[Dict], project_name: str = "Unknown", output_file: str = None) -> str:
        """Generate optimized HTML report."""
        by_type = {}
        by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for vuln in vulnerabilities:
            vtype = vuln['type']
            severity = vuln.get('severity', 'medium')
            by_type[vtype] = by_type.get(vtype, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1

        # Generate vulnerability rows efficiently
        vuln_rows = [
            f'<tr class="severity-{vuln.get("severity", "medium")}">'
            f'<td><span class="badge severity-{vuln.get("severity", "medium")}">{vuln.get("severity", "medium")}</span></td>'
            f'<td><code>{vuln["type"]}</code></td>'
            f'<td><code>{vuln.get("file", "N/A")}</code></td>'
            f'<td>{vuln.get("line", 0)}</td>'
            f'<td><code>{vuln.get("sink", "N/A")}</code></td>'
            f'</tr>'
            for vuln in vulnerabilities
        ]

        # Generate summary cards
        summary_html = f"""
            <div class="summary-card critical">
                <h3>{by_severity['critical']}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h3>{by_severity['high']}</h3>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h3>{by_severity['medium']}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card low">
                <h3>{by_severity['low']}</h3>
                <p>Low</p>
            </div>
        """

        # Generate charts data
        type_chart_data = json.dumps([
            {'type': k, 'count': v} for k, v in by_type.items()
        ])

        # Fill template
        html = self.template.format(
            project_name=project_name,
            scan_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_files=len(set(v.get('file') for v in vulnerabilities)),
            total_vulnerabilities=len(vulnerabilities),
            summary_cards=summary_html,
            vulnerability_rows=''.join(vuln_rows),
            chart_data=type_chart_data
        )

        if output_file:
            with open(output_file, 'w') as f:
                f.write(html)

        return html

    def _get_template(self) -> str:
        """Get HTML template."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {project_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f7fa;
            color: #333;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }}
        h1 {{
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 32px;
        }}
        .metadata {{
            color: #7f8c8d;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
        }}
        .summary-card.critical {{ background: #e74c3c; }}
        .summary-card.high {{ background: #e67e22; }}
        .summary-card.medium {{ background: #f39c12; }}
        .summary-card.low {{ background: #3498db; }}
        .summary-card h3 {{
            font-size: 36px;
            margin-bottom: 5px;
        }}
        .summary-card p {{
            font-size: 14px;
            text-transform: uppercase;
            opacity: 0.9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th {{
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid #ecf0f1;
            font-size: 14px;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .severity-critical {{ background: #e74c3c; color: white; }}
        .severity-high {{ background: #e67e22; color: white; }}
        .severity-medium {{ background: #f39c12; color: white; }}
        .severity-low {{ background: #3498db; color: white; }}
        code {{
            background: #ecf0f1;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 13px;
        }}
        .filter-controls {{
            margin: 20px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
        }}
        .filter-controls select {{
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-right: 10px;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Scan Report</h1>
        <div class="metadata">
            <strong>Project:</strong> {project_name} |
            <strong>Date:</strong> {scan_date} |
            <strong>Files Scanned:</strong> {total_files}
        </div>

        <div class="summary">
            {summary_cards}
        </div>

        <h2>📊 Vulnerabilities ({total_vulnerabilities})</h2>

        <div class="filter-controls">
            <label>Filter by Severity:</label>
            <select id="severityFilter" onchange="filterTable()">
                <option value="all">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>
            <label>Filter by Type:</label>
            <select id="typeFilter" onchange="filterTable()">
                <option value="all">All Types</option>
            </select>
        </div>

        <table id="vulnTable">
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>File</th>
                    <th>Line</th>
                    <th>Sink</th>
                </tr>
            </thead>
            <tbody>
                {vulnerability_rows}
            </tbody>
        </table>

        <div class="footer">
            Generated by PHP Security Scanner v2.1 |
            <a href="https://github.com/your-org/php-security-scanner">GitHub</a>
        </div>
    </div>

    <script>
        function filterTable() {{
            const severityFilter = document.getElementById('severityFilter').value;
            const typeFilter = document.getElementById('typeFilter').value;
            const table = document.getElementById('vulnTable');
            const rows = table.getElementsByTagName('tr');

            for (let i = 1; i < rows.length; i++) {{
                const row = rows[i];
                let showRow = true;

                if (severityFilter !== 'all' && !row.className.includes(severityFilter)) {{
                    showRow = false;
                }}

                row.style.display = showRow ? '' : 'none';
            }}
        }}
    </script>
</body>
</html>
        """
