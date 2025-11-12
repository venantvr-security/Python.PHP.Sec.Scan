# Plugin System Documentation

## Overview

The PHP Security Scanner includes a plugin system that allows you to extend functionality without modifying core code. Plugins can:

- Hook into scan lifecycle events
- Add custom security rules
- Export metrics to monitoring systems
- Send notifications
- Enforce security policies
- Process and filter vulnerabilities

## Built-in Plugins

### WordPress Plugin

Detects WordPress projects and tracks hooks/actions.

```python
from plugins import WordPressPlugin

plugin = WordPressPlugin()
```

Features:

- Auto-detects WordPress installations (wp-config.php, wp-load.php)
- Tracks `add_action()` and `add_filter()` calls
- Adds WordPress-specific statistics to scan results

### Performance Plugin

Monitors and reports scan performance metrics.

```python
from plugins import PerformancePlugin

plugin = PerformancePlugin()
```

Features:

- Tracks total scan time
- Measures per-file analysis time
- Identifies slowest files
- Calculates average processing time

### Notification Plugin

Sends webhook notifications on scan completion.

```python
from plugins import NotificationPlugin

plugin = NotificationPlugin(webhook_url="https://hooks.slack.com/...")
```

Features:

- Sends POST requests to webhook URLs
- Includes vulnerability counts and severity breakdown
- Configurable via environment variable `WEBHOOK_URL`

## Custom Plugins

### Custom Rules Plugin

Add organization-specific security checks.

```python
from plugins.custom_rules import CustomRulesPlugin

plugin = CustomRulesPlugin()
```

Features:

- Detects deprecated MySQL functions (`mysql_query`, etc.)
- Identifies dangerous patterns (`extract`, `parse_str`, `$$`)
- Can upgrade severity based on function usage
- Adds custom warnings to scan results

### Metrics Exporter Plugin

Export metrics to monitoring systems (Prometheus, JSON).

```python
from plugins.metrics_exporter import MetricsExporterPlugin

# Export to JSON
plugin = MetricsExporterPlugin(export_format='json', output_dir='metrics')

# Export to Prometheus format
plugin = MetricsExporterPlugin(export_format='prometheus', output_dir='metrics')
```

Features:

- JSON format for general use
- Prometheus text format for monitoring
- Tracks vulnerabilities by type and severity
- Includes cache hit rate and performance metrics

### Slack Notifier Plugin

Send rich notifications to Slack channels.

```python
from plugins.slack_notifier import SlackNotifierPlugin

plugin = SlackNotifierPlugin(
    webhook_url="https://hooks.slack.com/...",
    mention_on_critical=True
)
```

Features:

- Rich message formatting with blocks
- Color-coded by severity
- Channel mentions for critical vulnerabilities
- Scan start and completion notifications

### Security Policy Plugin

Enforce organizational security policies.

```python
from plugins.security_policy import SecurityPolicyPlugin

plugin = SecurityPolicyPlugin(
    max_critical=0,    # No critical vulnerabilities allowed
    max_high=5,        # Maximum 5 high severity
    max_total=50,      # Maximum 50 total vulnerabilities
    fail_on_violation=True
)
```

Features:

- Configurable thresholds by severity
- Can fail builds on policy violations (exit code 1)
- Detailed violation reporting
- Perfect for CI/CD pipelines

## Using Plugins

### CLI Usage

Enable plugins with the CLI:

```bash
# Enable default plugins (WordPress, Performance)
python cli_v2.py --dir /path/to/project --enable-plugins

# Load custom plugins from directory
python cli_v2.py --dir /path/to/project \
  --enable-plugins \
  --load-plugins-from ./my-plugins
```

### Programmatic Usage

```python
from plugins import PluginManager, WordPressPlugin, PerformancePlugin
from plugins.slack_notifier import SlackNotifierPlugin
from workers.parallel_scanner import ParallelScanner

# Initialize plugin manager
manager = PluginManager()

# Register built-in plugins
manager.register(WordPressPlugin())
manager.register(PerformancePlugin())

# Register custom plugin
manager.register(SlackNotifierPlugin(webhook_url="https://..."))

# Create scanner with plugins
scanner = ParallelScanner(
    vuln_types=['sql_injection', 'xss', 'rce'],
    plugin_manager=manager
)

# Scan with plugin hooks
scan_context = {'root_path': '/path/to/project', 'project': 'myapp'}
results = scanner.scan_files(files, scan_context=scan_context)
```

## Creating Custom Plugins

### Basic Plugin Structure

```python
from typing import Dict, Any, Optional
from plugins import ScannerPlugin


class MyCustomPlugin(ScannerPlugin):
    """My custom security plugin."""

    def __init__(self):
        super().__init__()
        self.name = "My Custom Plugin"
        self.version = "1.0.0"

    def on_scan_start(self, scan_context: Dict[str, Any]):
        """Called when scan starts."""
        print(f"{self.name} initialized")

    def on_file_scanned(self, file_path: str, results: Dict[str, Any]):
        """Called after each file is scanned."""
        # Add custom logic here
        pass

    def on_scan_complete(self, scan_results: Dict[str, Any]):
        """Called when scan completes."""
        # Add summary logic here
        pass

    def on_vulnerability_found(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Called for each vulnerability. Can modify or filter."""
        # Return modified vulnerability or None to filter
        return vulnerability
```

### Plugin Hooks

#### `on_scan_start(scan_context)`

Called before scanning begins.

Parameters:

- `scan_context`: Dict with `root_path`, `project`, etc.

Use cases:

- Initialize plugin state
- Detect project type
- Print startup messages

#### `on_file_scanned(file_path, results)`

Called after each file is analyzed.

Parameters:

- `file_path`: Path to scanned file
- `results`: Dict with `vulnerabilities`, `warnings`, `analysis_time`, etc.

Use cases:

- Track per-file metrics
- Add custom warnings
- Detect patterns in code

#### `on_scan_complete(scan_results)`

Called after all files are scanned.

Parameters:

- `scan_results`: Dict with `files`, `statistics`

Use cases:

- Generate reports
- Send notifications
- Export metrics
- Enforce policies

#### `on_vulnerability_found(vulnerability)`

Called for each vulnerability before reporting.

Parameters:

- `vulnerability`: Dict with `type`, `file`, `line`, `severity`, `sink`

Returns:

- Modified vulnerability dict
- `None` to filter out the vulnerability

Use cases:

- Modify severity
- Add context
- Filter false positives
- Track custom metrics

### Example: Rate Limiting Plugin

```python
from plugins import ScannerPlugin
from collections import Counter


class RateLimitPlugin(ScannerPlugin):
    """Track API calls that might hit rate limits."""

    def __init__(self):
        super().__init__()
        self.name = "Rate Limit Tracker"
        self.api_calls = Counter()

    def on_scan_start(self, scan_context):
        self.api_calls.clear()

    def on_file_scanned(self, file_path, results):
        # Simple pattern matching (in production, use AST)
        with open(file_path, 'r') as f:
            content = f.read()

        # Track API calls
        if 'wp_remote_get' in content:
            self.api_calls['wp_remote_get'] += content.count('wp_remote_get')
        if 'curl_exec' in content:
            self.api_calls['curl_exec'] += content.count('curl_exec')

    def on_scan_complete(self, scan_results):
        if self.api_calls:
            print("\n⚡ API Call Summary:")
            for func, count in self.api_calls.most_common():
                print(f"  {func}: {count} calls")
```

## Testing Plugins

```python
# tests/test_my_plugin.py
from plugins.my_plugin import MyCustomPlugin


def test_plugin_basic():
    plugin = MyCustomPlugin()

    scan_context = {'project': 'test'}
    plugin.on_scan_start(scan_context)

    results = {}
    plugin.on_file_scanned('/test/file.php', results)

    plugin.on_scan_complete({'files': {}})


def test_plugin_vulnerability_processing():
    plugin = MyCustomPlugin()

    vuln = {'type': 'xss', 'severity': 'low'}
    processed = plugin.on_vulnerability_found(vuln)

    assert processed is not None
```

Run tests:

```bash
pytest tests/test_my_plugin.py -v
```

## Best Practices

1. **Keep plugins focused**: Each plugin should do one thing well
2. **Handle errors gracefully**: Use try/except to avoid breaking scans
3. **Minimize performance impact**: Avoid heavy computation in `on_file_scanned`
4. **Respect privacy**: Don't send sensitive code to external services
5. **Document configuration**: Make it clear what environment variables are needed
6. **Provide examples**: Include sample usage in docstrings
7. **Test thoroughly**: Write unit tests for all plugin functionality

## Environment Variables

Plugins often use environment variables for configuration:

```bash
# Slack webhook URL
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."

# Generic webhook URL
export WEBHOOK_URL="https://..."

# Prometheus pushgateway
export PROMETHEUS_PUSHGATEWAY="http://localhost:9091"
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run security scan with plugins
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
  run: |
    python cli_v2.py \
      --dir . \
      --enable-plugins \
      --project ${{ github.repository }}
```

### GitLab CI

```yaml
security_scan:
  script:
    - python cli_v2.py --dir . --enable-plugins
  variables:
    SLACK_WEBHOOK_URL: $SLACK_WEBHOOK_URL
```

## Plugin Auto-loading

Place plugins in the `plugins/` directory and they'll be auto-discovered:

```python
manager = PluginManager()
manager.load_from_directory('plugins')
```

Requirements:

- File must end with `.py`
- Must contain a class that inherits from `ScannerPlugin`
- Class must not be `ScannerPlugin` itself

## Troubleshooting

**Plugin not loading:**

- Check the file is in the correct directory
- Verify the class inherits from `ScannerPlugin`
- Look for import errors in the plugin file

**Webhook notifications not sent:**

- Verify the webhook URL is correct
- Check `requests` library is installed: `pip install requests`
- Test the webhook manually with curl

**Performance issues:**

- Profile plugin with `cProfile`
- Move heavy operations to `on_scan_complete`
- Use caching for expensive lookups

**Tests failing:**

- Check for absolute paths in tests
- Use `tempfile.TemporaryDirectory()` for file operations
- Mock external services (webhooks, APIs)
