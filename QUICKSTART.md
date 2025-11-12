# Quick Start Guide - PHP Security Scanner

## Installation (< 1 minute)

```bash
# Clone repository
git clone <repo-url>
cd Python.PHP.Sec.Scan

# Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python cli.py --init-db
```

## Usage Options

### 1. Command Line (Fastest)

```bash
# Scan a project
python cli.py scan --dir /path/to/php/project --project myapp

# With all features enabled
python cli.py scan \
  --dir /path/to/wordpress \
  --project myblog \
  --enable-plugins \
  --export-sarif report.sarif

# Export existing scan
python cli.py export --scan-id 1 --format sarif --output report.sarif

# View statistics
python cli.py stats --project myapp

# Manage suppressions
python cli.py suppress add \
  --file app.php \
  --line 42 \
  --type xss \
  --reason "False positive - input validated upstream"
```

### 2. Web Interface (Best UX)

```bash
# Start web server
python web_interface.py

# Open browser
# → http://localhost:5000

# Features:
# - Point-and-click scan launcher
# - Real-time vulnerability viewing
# - Project management
# - Export to SARIF/JSON
# - Modern UI with charts
```

### 3. REST API (For Integration)

```bash
# Start API server
uvicorn api.main:app --reload

# Open docs
# → http://localhost:8000/docs

# Example: Trigger scan via API
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "project": "myapp",
    "path": "/path/to/project",
    "vuln_types": ["sql_injection", "xss", "rce"]
  }'

# Get results
curl http://localhost:8000/vulnerabilities/{scan_id}

# Export SARIF
curl http://localhost:8000/export/{scan_id}/sarif > report.sarif
```

### 4. Python API (For Scripting)

```python
from workers.parallel_scanner import ParallelScanner
from plugins import PluginManager, WordPressPlugin

# Setup
manager = PluginManager()
manager.register(WordPressPlugin())

scanner = ParallelScanner(
    vuln_types=['sql_injection', 'xss', 'rce'],
    max_workers=12,
    plugin_manager=manager
)

# Scan
php_files = list(Path('/project').rglob('*.php'))
results = scanner.scan_files(php_files)

# Get statistics
stats = scanner.get_statistics(results)
print(f"Found {stats['total_vulnerabilities']} vulnerabilities")
```

## Example Workflows

### Workflow 1: Quick Security Check

```bash
# Scan current directory
python cli.py scan --dir . --project myproject

# View results
python cli.py stats --project myproject

# Export for GitHub Security
python cli.py export --scan-id latest --format sarif --output results.sarif
```

### Workflow 2: WordPress Security Audit

```bash
# Scan WordPress site with WP plugin
python cli.py scan \
  --dir /var/www/wordpress \
  --project client-site \
  --enable-plugins \
  --vuln-types sql_injection xss rce

# Generate HTML report
python cli.py export --scan-id latest --format html --output report.html

# Email report to client
```

### Workflow 3: CI/CD Integration

```yaml
# .github/workflows/security.yml
- name: Security Scan
  run: |
    python cli.py scan --dir . --project ${{ github.repository }}
    python cli.py export --scan-id latest --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Workflow 4: Batch Project Scanning

```bash
# Scan multiple projects
python scripts/batch_scan.py /var/www/projects --output reports/

# Generates:
# - reports/batch_summary_20250112.json
# - reports/project1_20250112.sarif
# - reports/project2_20250112.sarif
# - reports/batch_report_20250112.html
```

## Common Commands

```bash
# Initialize
python cli.py --init-db                    # Setup database

# Scanning
python cli.py scan --dir /app              # Basic scan
python cli.py scan --files a.php b.php     # Specific files
python cli.py scan --dir /app --no-cache   # Force re-analysis

# Exporting
python cli.py export --scan-id 1 --format sarif -o r.sarif
python cli.py export --scan-id latest --format json -o r.json
python cli.py export --scan-id 1 --format html -o report.html

# Management
python cli.py projects list                # List all projects
python cli.py stats --project myapp        # Project statistics
python cli.py cache clear                  # Clear AST cache
python cli.py suppress list                # List suppressions

# Web Interface
python web_interface.py                    # Start web UI (port 5000)

# API Server
uvicorn api.main:app --reload              # Start API (port 8000)
```

## Performance Tips

1. **Enable Caching** (default): 20x faster on repeated scans
2. **Use Workers**: `--workers 12` for multi-threading (10x faster)
3. **Enable Plugins**: Only when needed (adds ~10% overhead)
4. **Incremental Scans**: Cache automatically skips unchanged files

## Troubleshooting

**"No PHP files found"**
```bash
# Check path is correct
ls /path/to/project/*.php

# Ensure directory has .php files
find /path/to/project -name "*.php"
```

**"Database error"**
```bash
# Reinitialize database
python cli.py --init-db

# Check permissions
ls -la scanner.db
```

**"Import errors"**
```bash
# Ensure virtual environment is activated
source .venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

**"Slow scans"**
```bash
# Increase workers
python cli.py scan --dir /app --workers 16

# Use cache
python cli.py scan --dir /app  # Cache enabled by default

# Check cache stats
python cli.py cache stats
```

## Next Steps

- Read [README.md](README.md) for full documentation
- See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for system design
- Check [PLUGINS.md](docs/PLUGINS.md) for plugin development
- Run tests: `pytest -v`
- Join community: [GitHub Issues](https://github.com/...)

## Help

```bash
# CLI help
python cli.py --help
python cli.py scan --help
python cli.py export --help

# API docs
# Start API: uvicorn api.main:app --reload
# Open: http://localhost:8000/docs

# Web UI
# Start: python web_interface.py
# Open: http://localhost:5000
```

---

**Ready to scan in < 2 minutes!** 🚀
