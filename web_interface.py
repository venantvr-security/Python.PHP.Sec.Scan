#!/usr/bin/env python3
"""
PHP Security Scanner - Web Interface
Flask-based interactive dashboard for scan management.
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import json
from pathlib import Path
from datetime import datetime

from db.connection import get_session
from db.models import Project, Scan, Vulnerability, ScanStatus
from workers.parallel_scanner import ParallelScanner
from exporters.sarif import SARIFExporter
from plugins import PluginManager, WordPressPlugin, PerformancePlugin

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Store active scans
active_scans = {}


@app.route('/')
def index():
    """Home page with project selection."""
    with get_session() as session:
        projects = session.query(Project).all()
        recent_scans = session.query(Scan).order_by(Scan.created_at.desc()).limit(10).all()

    return render_template('index.html', projects=projects, recent_scans=recent_scans)


@app.route('/api/projects', methods=['GET'])
def get_projects():
    """List all projects."""
    with get_session() as session:
        projects = session.query(Project).all()
        return jsonify([{
            'id': p.id,
            'name': p.name,
            'root_path': p.root_path,
            'is_wordpress': p.is_wordpress,
            'scan_count': len(p.scans)
        } for p in projects])


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan."""
    data = request.json
    project_path = data.get('path')
    project_name = data.get('name', 'default')
    vuln_types = data.get('vuln_types', ['sql_injection', 'xss', 'rce'])
    enable_plugins = data.get('enable_plugins', False)

    if not project_path or not os.path.isdir(project_path):
        return jsonify({'error': 'Invalid project path'}), 400

    # Create scanner
    plugin_manager = None
    if enable_plugins:
        plugin_manager = PluginManager()
        plugin_manager.register(WordPressPlugin())
        plugin_manager.register(PerformancePlugin())

    scanner = ParallelScanner(
        vuln_types=vuln_types,
        max_workers=12,
        use_cache=True,
        plugin_manager=plugin_manager
    )

    # Find PHP files
    files = [str(f) for f in Path(project_path).rglob('*.php')]

    if not files:
        return jsonify({'error': 'No PHP files found'}), 400

    # Run scan (async in production, sync for demo)
    scan_context = {'root_path': project_path, 'project': project_name}
    results = scanner.scan_files(files, scan_context=scan_context)
    stats = scanner.get_statistics(results)

    # Save to database
    with get_session() as session:
        project = session.query(Project).filter_by(name=project_name).first()
        if not project:
            project = Project(name=project_name, root_path=project_path)
            session.add(project)
            session.flush()

        scan = Scan(
            project_id=project.id,
            vuln_types=vuln_types,
            status=ScanStatus.COMPLETED,
            total_files=stats['total_files'],
            scanned_files=stats['total_files'],
            total_vulnerabilities=stats['total_vulnerabilities'],
            duration_seconds=stats['total_analysis_time'],
        )
        session.add(scan)
        session.flush()

        # Save vulnerabilities
        for filepath, file_result in results.items():
            for vuln in file_result.get('vulnerabilities', []):
                vuln_record = Vulnerability(
                    scan_id=scan.id,
                    vuln_type=vuln.get('type'),
                    filepath=filepath,
                    line_number=vuln.get('line', 0),
                    sink_function=vuln.get('sink'),
                    tainted_variable=vuln.get('variable'),
                    trace=vuln.get('trace'),
                )
                session.add(vuln_record)

        session.commit()
        scan_id = scan.id

    return jsonify({
        'scan_id': scan_id,
        'status': 'completed',
        'statistics': stats
    })


@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get scan details."""
    with get_session() as session:
        scan = session.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        vulns = session.query(Vulnerability).filter_by(scan_id=scan_id).all()

        return jsonify({
            'id': scan.id,
            'project': scan.project.name,
            'status': scan.status.value,
            'total_files': scan.total_files,
            'total_vulnerabilities': scan.total_vulnerabilities,
            'duration': scan.duration_seconds,
            'created_at': scan.created_at.isoformat(),
            'vulnerabilities': [{
                'type': v.vuln_type,
                'file': v.filepath,
                'line': v.line_number,
                'severity': v.severity.value if hasattr(v.severity, 'value') else 'medium',
                'sink': v.sink_function,
                'variable': v.tainted_variable,
                'trace': v.trace,
            } for v in vulns]
        })


@app.route('/api/scan/<int:scan_id>/export/<format>', methods=['GET'])
def export_scan(scan_id, format):
    """Export scan results."""
    with get_session() as session:
        scan = session.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        vulns = session.query(Vulnerability).filter_by(scan_id=scan_id).all()
        vuln_dicts = [{
            'type': v.vuln_type,
            'file': v.filepath,
            'line': v.line_number,
            'severity': v.severity.value if hasattr(v.severity, 'value') else 'medium',
            'sink': v.sink_function,
            'variable': v.tainted_variable,
            'trace': v.trace,
        } for v in vulns]

        if format == 'sarif':
            exporter = SARIFExporter()
            sarif = exporter.export(vuln_dicts)
            return jsonify(sarif)
        elif format == 'json':
            return jsonify({
                'scan_id': scan_id,
                'project': scan.project.name,
                'vulnerabilities': vuln_dicts
            })

        return jsonify({'error': 'Invalid format'}), 400


@app.route('/dashboard')
def dashboard():
    """Dashboard view."""
    return render_template('dashboard.html')


@app.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    """View scan results."""
    with get_session() as session:
        scan = session.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return "Scan not found", 404

        vulns = session.query(Vulnerability).filter_by(scan_id=scan_id).all()

        return render_template('scan_detail.html', scan=scan, vulnerabilities=vulns)


if __name__ == '__main__':
    # Create templates directory if not exists
    os.makedirs('templates', exist_ok=True)

    # Create basic templates if they don't exist
    if not os.path.exists('templates/index.html'):
        with open('templates/index.html', 'w') as f:
            f.write('''<!DOCTYPE html>
<html>
<head>
    <title>PHP Security Scanner</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { font-size: 1.1em; opacity: 0.9; }
        .card { background: white; border-radius: 8px; padding: 30px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h2 { color: #333; margin-bottom: 20px; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #555; font-weight: 600; }
        .form-group input, .form-group select { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .form-group input:focus { outline: none; border-color: #667eea; }
        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; font-weight: 600; transition: transform 0.2s; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(102, 126, 234, 0.4); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .projects-list { list-style: none; }
        .projects-list li { padding: 15px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .projects-list li:hover { background: #f9f9f9; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .badge.wp { background: #21759b; color: white; }
        .scan-item { padding: 15px; border-left: 4px solid #667eea; margin-bottom: 10px; background: #f9f9f9; }
        .scan-item:hover { background: #f0f0f0; cursor: pointer; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px; }
        .stat-card { padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 8px; text-align: center; }
        .stat-card .number { font-size: 2em; font-weight: bold; }
        .stat-card .label { opacity: 0.9; margin-top: 5px; }
        #status { margin-top: 20px; padding: 15px; border-radius: 4px; display: none; }
        #status.success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        #status.error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        #status.info { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
        .checkbox-group { display: flex; flex-wrap: wrap; gap: 15px; }
        .checkbox-group label { display: flex; align-items: center; cursor: pointer; }
        .checkbox-group input { margin-right: 8px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 PHP Security Scanner</h1>
        <p>Advanced Static Analysis for PHP Applications</p>
    </div>

    <div class="container">
        <div class="card">
            <h2>Start New Scan</h2>
            <form id="scanForm">
                <div class="form-group">
                    <label>Project Path</label>
                    <input type="text" id="projectPath" placeholder="/path/to/php/project" required>
                </div>
                <div class="form-group">
                    <label>Project Name</label>
                    <input type="text" id="projectName" placeholder="my-project" required>
                </div>
                <div class="form-group">
                    <label>Vulnerability Types</label>
                    <div class="checkbox-group">
                        <label><input type="checkbox" name="vuln" value="sql_injection" checked> SQL Injection</label>
                        <label><input type="checkbox" name="vuln" value="xss" checked> XSS</label>
                        <label><input type="checkbox" name="vuln" value="rce" checked> RCE</label>
                        <label><input type="checkbox" name="vuln" value="file_inclusion"> File Inclusion</label>
                        <label><input type="checkbox" name="vuln" value="command_injection"> Command Injection</label>
                        <label><input type="checkbox" name="vuln" value="path_traversal"> Path Traversal</label>
                    </div>
                </div>
                <div class="form-group">
                    <label><input type="checkbox" id="enablePlugins"> Enable Plugins (WordPress, Performance)</label>
                </div>
                <button type="submit" class="btn" id="scanBtn">🚀 Start Scan</button>
            </form>
            <div id="status"></div>
        </div>

        <div class="card">
            <h2>📊 Recent Scans</h2>
            <div id="recentScans">
                {% for scan in recent_scans %}
                <div class="scan-item" onclick="location.href='/scan/{{ scan.id }}'">
                    <strong>{{ scan.project.name }}</strong> -
                    {{ scan.created_at.strftime('%Y-%m-%d %H:%M') }} -
                    <span style="color: {% if scan.total_vulnerabilities > 0 %}#dc3545{% else %}#28a745{% endif %};">
                        {{ scan.total_vulnerabilities }} vulnerabilities
                    </span>
                </div>
                {% else %}
                <p>No scans yet. Start your first scan above!</p>
                {% endfor %}
            </div>
        </div>

        <div class="card">
            <h2>💼 Projects</h2>
            <ul class="projects-list" id="projectsList">
                {% for project in projects %}
                <li>
                    <div>
                        <strong>{{ project.name }}</strong>
                        {% if project.is_wordpress %}<span class="badge wp">WordPress</span>{% endif %}
                        <br>
                        <small style="color: #777;">{{ project.root_path }}</small>
                    </div>
                    <div>{{ len(project.scans) }} scans</div>
                </li>
                {% else %}
                <li>No projects yet</li>
                {% endfor %}
            </ul>
        </div>
    </div>

    <script>
        document.getElementById('scanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('scanBtn');
            const status = document.getElementById('status');

            btn.disabled = true;
            btn.textContent = '⏳ Scanning...';
            status.style.display = 'block';
            status.className = 'info';
            status.textContent = 'Scan in progress...';

            const vulnTypes = Array.from(document.querySelectorAll('input[name="vuln"]:checked')).map(cb => cb.value);

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        path: document.getElementById('projectPath').value,
                        name: document.getElementById('projectName').value,
                        vuln_types: vulnTypes,
                        enable_plugins: document.getElementById('enablePlugins').checked
                    })
                });

                const data = await response.json();

                if (response.ok) {
                    status.className = 'success';
                    status.innerHTML = `✓ Scan completed!<br>
                        Files: ${data.statistics.total_files}<br>
                        Vulnerabilities: ${data.statistics.total_vulnerabilities}<br>
                        Time: ${data.statistics.total_analysis_time.toFixed(2)}s<br>
                        <a href="/scan/${data.scan_id}">View Results →</a>`;
                    setTimeout(() => location.reload(), 2000);
                } else {
                    status.className = 'error';
                    status.textContent = '✗ Error: ' + data.error;
                }
            } catch (error) {
                status.className = 'error';
                status.textContent = '✗ Error: ' + error.message;
            } finally {
                btn.disabled = false;
                btn.textContent = '🚀 Start Scan';
            }
        });
    </script>
</body>
</html>''')

    print("="*60)
    print("PHP Security Scanner - Web Interface")
    print("="*60)
    print("\n✓ Server starting on http://127.0.0.1:5000")
    print("\nFeatures:")
    print("  • Interactive scan launcher")
    print("  • Real-time results viewing")
    print("  • Project management")
    print("  • SARIF/JSON export")
    print("\n" + "="*60)

    app.run(debug=True, host='0.0.0.0', port=5000)
