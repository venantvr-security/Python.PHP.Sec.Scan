# plugins/__init__.py
"""Plugin system for extending scanner functionality."""

import importlib
import inspect
import os
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional


class ScannerPlugin(ABC):
    """Base class for scanner plugins."""

    def __init__(self):
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.enabled = True

    @abstractmethod
    def on_scan_start(self, scan_context: Dict[str, Any]):
        """Called when scan starts."""
        pass

    @abstractmethod
    def on_file_scanned(self, file_path: str, results: Dict[str, Any]):
        """Called after each file is scanned."""
        pass

    @abstractmethod
    def on_scan_complete(self, scan_results: Dict[str, Any]):
        """Called when scan completes."""
        pass

    def on_vulnerability_found(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Called when vulnerability is found. Can modify or filter."""
        return vulnerability


class WordPressPlugin(ScannerPlugin):
    """WordPress-specific analysis plugin."""

    def __init__(self):
        super().__init__()
        self.name = "WordPress Security Plugin"
        self.wp_functions = set()
        self.wp_hooks = []

    def on_scan_start(self, scan_context: Dict[str, Any]):
        """Detect if project is WordPress."""
        root_path = scan_context.get('root_path', '')
        wp_files = ['wp-config.php', 'wp-load.php', 'wp-settings.php']

        is_wp = any(
            os.path.exists(os.path.join(root_path, f))
            for f in wp_files
        )

        scan_context['is_wordpress'] = is_wp
        if is_wp:
            print(f"✓ WordPress project detected")

    def on_file_scanned(self, file_path: str, results: Dict[str, Any]):
        """Track WordPress functions and hooks."""
        # Detect WP hook registrations
        if 'add_action' in str(results):
            self.wp_hooks.append(('action', file_path))
        if 'add_filter' in str(results):
            self.wp_hooks.append(('filter', file_path))

    def on_scan_complete(self, scan_results: Dict[str, Any]):
        """Add WordPress-specific stats."""
        scan_results['wordpress'] = {
            'hooks_found': len(self.wp_hooks),
            'actions': len([h for h in self.wp_hooks if h[0] == 'action']),
            'filters': len([h for h in self.wp_hooks if h[0] == 'filter'])
        }


class PerformancePlugin(ScannerPlugin):
    """Performance monitoring plugin."""

    def __init__(self):
        super().__init__()
        self.name = "Performance Monitor"
        self.start_time = None
        self.file_times = []

    def on_scan_start(self, scan_context: Dict[str, Any]):
        """Start timing."""
        from datetime import datetime

        self.start_time = datetime.now()

    def on_file_scanned(self, file_path: str, results: Dict[str, Any]):
        """Track file scan time."""
        if 'scan_time' in results:
            self.file_times.append((file_path, results['scan_time']))

    def on_scan_complete(self, scan_results: Dict[str, Any]):
        """Add performance stats."""
        from datetime import datetime

        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            scan_results['performance'] = {
                'total_time': duration,
                'avg_file_time': sum(t for _, t in self.file_times) / len(self.file_times) if self.file_times else 0,
                'slowest_files': sorted(self.file_times, key=lambda x: x[1], reverse=True)[:5]
            }


class NotificationPlugin(ScannerPlugin):
    """Send notifications on scan completion."""

    def __init__(self, webhook_url: Optional[str] = None):
        super().__init__()
        self.name = "Notification Plugin"
        self.webhook_url = webhook_url or os.getenv('WEBHOOK_URL')

    def on_scan_start(self, scan_context: Dict[str, Any]):
        """No action on start."""
        pass

    def on_file_scanned(self, file_path: str, results: Dict[str, Any]):
        """No action per file."""
        pass

    def on_scan_complete(self, scan_results: Dict[str, Any]):
        """Send notification."""
        if not self.webhook_url:
            return

        try:
            import requests

            critical = sum(1 for v in scan_results.get('vulnerabilities', [])
                           if v.get('severity') == 'critical')

            payload = {
                'text': f"🔒 Security Scan Complete\\n"
                        f"Project: {scan_results.get('project', 'Unknown')}\\n"
                        f"Vulnerabilities: {len(scan_results.get('vulnerabilities', []))}\\n"
                        f"Critical: {critical}"
            }

            requests.post(self.webhook_url, json=payload, timeout=5)
        except Exception as e:
            print(f"Notification error: {e}")


class PluginManager:
    """Manage scanner plugins."""

    def __init__(self):
        self.plugins: List[ScannerPlugin] = []

    def register(self, plugin: ScannerPlugin):
        """Register a plugin."""
        self.plugins.append(plugin)
        print(f"✓ Plugin registered: {plugin.name}")

    def load_from_directory(self, plugin_dir: str = "plugins"):
        """Load plugins from directory."""
        if not os.path.exists(plugin_dir):
            return

        for file in os.listdir(plugin_dir):
            if file.endswith('.py') and not file.startswith('__'):
                module_name = file[:-3]
                try:
                    module = importlib.import_module(f'plugins.{module_name}')
                    for name, obj in inspect.getmembers(module):
                        if (inspect.isclass(obj) and
                                issubclass(obj, ScannerPlugin) and
                                obj != ScannerPlugin):
                            self.register(obj())
                except Exception as e:
                    print(f"Error loading plugin {module_name}: {e}")

    def trigger_scan_start(self, scan_context: Dict[str, Any]):
        """Trigger scan start hook."""
        for plugin in self.plugins:
            if plugin.enabled:
                try:
                    plugin.on_scan_start(scan_context)
                except Exception as e:
                    print(f"Plugin error ({plugin.name}): {e}")

    def trigger_file_scanned(self, file_path: str, results: Dict[str, Any]):
        """Trigger file scanned hook."""
        for plugin in self.plugins:
            if plugin.enabled:
                try:
                    plugin.on_file_scanned(file_path, results)
                except Exception as e:
                    print(f"Plugin error ({plugin.name}): {e}")

    def trigger_scan_complete(self, scan_results: Dict[str, Any]):
        """Trigger scan complete hook."""
        for plugin in self.plugins:
            if plugin.enabled:
                try:
                    plugin.on_scan_complete(scan_results)
                except Exception as e:
                    print(f"Plugin error ({plugin.name}): {e}")

    def process_vulnerability(self, vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process vulnerability through plugin chain."""
        result = vulnerability
        for plugin in self.plugins:
            if plugin.enabled and result:
                result = plugin.on_vulnerability_found(result)
        return result
