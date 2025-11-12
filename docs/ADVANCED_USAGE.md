# Advanced Usage Guide

## Table of Contents

1. [Performance Optimization](#performance-optimization)
2. [Custom Workflows](#custom-workflows)
3. [CI/CD Integration](#cicd-integration)
4. [Plugin Development](#plugin-development)
5. [Advanced Reporting](#advanced-reporting)
6. [Trend Analysis](#trend-analysis)

## Performance Optimization

### Adaptive Worker Pools

```python
from optimization.smart_scheduler import AdaptiveWorkerPool

# Auto-detect optimal workers based on system load
workers = AdaptiveWorkerPool.get_optimal_workers()
scanner = ParallelScanner(vuln_types=types, max_workers=workers)
```

### Smart File Discovery

```python
from optimization.smart_scheduler import SmartScheduler

# Discover with intelligent exclusions
files = SmartScheduler.discover_php_files(
    '/app',
    exclude_patterns=['vendor/', 'node_modules/', 'cache/'],
    max_size=10 * 1024 * 1024  # Skip files > 10MB
)

# Prioritize by size and modification time
files = SmartScheduler.prioritize_files(files)
```

### Profiling Performance

```python
from optimization.profiler import profiler

# Profile your custom analyzers
@profiler.profile
def custom_analysis(files):
    # Your analysis code
    pass

# Run and print stats
custom_analysis(files)
profiler.print_stats()
```

## Custom Workflows

### Scan with Quality Gates

```python
from utils.metrics import ScanMetrics
from workers.parallel_scanner import ParallelScanner

scanner = ParallelScanner(vuln_types=['sql_injection', 'xss', 'rce'])
results = scanner.scan_directory('/app')

# Calculate quality score
quality_score = ScanMetrics.calculate_code_quality_score(results)
risk = ScanMetrics.risk_assessment(results)

# Quality gate
if risk['level'] in ['CRITICAL', 'HIGH']:
    print(f"❌ Quality gate failed: {risk['recommendation']}")
    exit(1)
elif quality_score < 70:
    print(f"⚠️  Quality score too low: {quality_score:.1f}/100")
    exit(1)
else:
    print(f"✅ Quality gate passed: {quality_score:.1f}/100")
    exit(0)
```

### Deduplication Workflow

```python
from utils.deduplicator import VulnerabilityDeduplicator, FalsePositiveFilter

# Scan
results = scanner.scan_directory('/app')
vulns = [v for r in results.values() for v in r['vulnerabilities']]

# Deduplicate
unique_vulns = VulnerabilityDeduplicator.deduplicate(vulns)

# Filter false positives
real_vulns, fp_vulns = FalsePositiveFilter.filter_false_positives(unique_vulns)

print(f"Total: {len(vulns)}, Unique: {len(unique_vulns)}, Real: {len(real_vulns)}, FP: {len(fp_vulns)}")
```

### Compare Scans

```python
from utils.deduplicator import VulnerabilityDeduplicator
import json

# Load previous scan
with open('previous_scan.json') as f:
    prev = json.load(f)['vulnerabilities']

# Run new scan
results = scanner.scan_directory('/app')
curr = [v for r in results.values() for v in r['vulnerabilities']]

# Compare
comparison = VulnerabilityDeduplicator.compare_scans(prev, curr)

print(f"🆕 New:     {comparison['summary']['new_count']}")
print(f"✅ Fixed:   {comparison['summary']['fixed_count']}")
print(f"📌 Existing: {comparison['summary']['existing_count']}")

# Fail if new critical vulnerabilities
new_critical = [v for v in comparison['new'] if v.get('severity') == 'critical']
if new_critical:
    print(f"❌ {len(new_critical)} new critical vulnerabilities!")
    exit(1)
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt

      - name: Run security scan
        run: |
          python3 cli.py scan --dir . --export-sarif results.sarif --output results.json

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif

      - name: Quality gate
        run: |
          python3 -c "
          import json
          with open('results.json') as f:
              data = json.load(f)
          critical = sum(1 for v in data['results'].values() for vuln in v['vulnerabilities'] if vuln.get('severity') == 'critical')
          if critical > 0:
              print(f'❌ {critical} critical vulnerabilities found!')
              exit(1)
          "
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security-scan:
  stage: test
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - python3 cli.py scan --dir . --output scan-results.json --export-sarif scan.sarif
    - python3 scripts/quality_gate.py scan-results.json
  artifacts:
    reports:
      sast: scan.sarif
    paths:
      - scan-results.json
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install -r requirements.txt'
                sh 'python3 cli.py scan --dir . --output results.json'

                script {
                    def results = readJSON file: 'results.json'
                    def critical = results.statistics.vulnerabilities_by_type['critical'] ?: 0

                    if (critical > 0) {
                        error("Critical vulnerabilities found: ${critical}")
                    }
                }
            }
        }
    }
}
```

## Plugin Development

### Custom Rule Plugin

```python
# plugins/custom_security_rules.py
from plugins import BasePlugin

class CustomSecurityPlugin(BasePlugin):
    def on_scan_start(self, context):
        print(f"Starting scan for {context['project']}")

    def on_file_scanned(self, filepath, result):
        # Check for custom patterns
        vulns = result['vulnerabilities']

        # Add custom check
        if 'password' in filepath.lower():
            for vuln in vulns:
                vuln['severity'] = 'high'  # Escalate severity

    def on_scan_complete(self, results):
        # Custom reporting
        total = sum(len(r['vulnerabilities']) for r in results['files'].values())
        print(f"Total vulnerabilities: {total}")

# Register plugin
plugin_manager.register(CustomSecurityPlugin())
```

## Advanced Reporting

### Executive Dashboard

```python
from utils.reporting import ReportGenerator
from utils.metrics import ScanMetrics

# Generate executive summary
summary = ReportGenerator.generate_executive_summary(scan_stats, vulnerabilities)
print(summary)

# Generate multiple formats
ReportGenerator.generate_json_report(scan_stats, vulnerabilities, 'report.json')
md = ReportGenerator.generate_markdown_report(scan_stats, vulnerabilities)
with open('SECURITY_REPORT.md', 'w') as f:
    f.write(md)
```

### Console Output with Colors

```python
from utils.reporting import ConsoleFormatter

for vuln in vulnerabilities[:10]:
    print(ConsoleFormatter.format_vulnerability(vuln))

print(ConsoleFormatter.format_summary(scan_stats))
```

## Trend Analysis

### Track Quality Over Time

```python
from utils.metrics import TrendAnalyzer
import json

analyzer = TrendAnalyzer()

# Load historical scans
for scan_file in ['scan1.json', 'scan2.json', 'scan3.json']:
    with open(scan_file) as f:
        data = json.load(f)
        analyzer.add_scan(data['statistics'])

# Get trend
trend = analyzer.get_trend()
print(f"Trend: {trend['trend']}")
print(f"Change: {trend['vulnerability_change']} ({trend['percentage_change']:.1f}%)")

# Alert on degradation
if trend['trend'] == 'degrading':
    print("⚠️  Security posture is degrading!")
```

### Continuous Monitoring

```python
import time
from pathlib import Path

def continuous_monitor(directory, interval=3600):
    """Monitor directory every hour."""
    from workers.parallel_scanner import ParallelScanner
    from utils.metrics import TrendAnalyzer

    analyzer = TrendAnalyzer()
    scanner = ParallelScanner(vuln_types=['sql_injection', 'xss', 'rce'])

    while True:
        results = scanner.scan_directory(directory)
        stats = scanner.get_statistics(results)

        analyzer.add_scan(stats)
        trend = analyzer.get_trend()

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
              f"Vulns: {stats['total_vulnerabilities']}, "
              f"Trend: {trend.get('trend', 'N/A')}")

        time.sleep(interval)

# Start monitoring
continuous_monitor('/app', interval=3600)
```

## Best Practices

1. **Always use caching** for repeated scans
2. **Set quality gates** in CI/CD pipelines
3. **Track trends** over time
4. **Deduplicate** before reporting
5. **Filter false positives** with caution
6. **Profile performance** on large codebases
7. **Use adaptive workers** for optimal parallelism
8. **Export to SARIF** for tool integration
