# plugins/slack_notifier.py
"""Plugin for sending notifications to Slack."""

import os
import json
from typing import Dict, Any, Optional
from plugins import ScannerPlugin


class SlackNotifierPlugin(ScannerPlugin):
    """Send rich notifications to Slack."""

    def __init__(self, webhook_url: Optional[str] = None, mention_on_critical: bool = True):
        super().__init__()
        self.name = "Slack Notifier Plugin"
        self.webhook_url = webhook_url or os.getenv('SLACK_WEBHOOK_URL')
        self.mention_on_critical = mention_on_critical
        self.scan_started = False

    def on_scan_start(self, scan_context: Dict[str, Any]):
        """Send scan start notification."""
        if not self.webhook_url:
            return

        self.scan_started = True
        project = scan_context.get('project', 'Unknown')

        payload = {
            'text': f'🔍 Security scan started for *{project}*',
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f'🔍 *Security Scan Started*\n\nProject: `{project}`\nPath: `{scan_context.get("root_path", "")}`'
                    }
                }
            ]
        }

        self._send_to_slack(payload)

    def on_file_scanned(self, file_path: str, results: Dict[str, Any]):
        """No action per file (would be too noisy)."""
        pass

    def on_scan_complete(self, scan_results: Dict[str, Any]):
        """Send comprehensive scan completion notification."""
        if not self.webhook_url or not self.scan_started:
            return

        stats = scan_results.get('statistics', {})
        total_vulns = stats.get('total_vulnerabilities', 0)

        # Count by severity
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        for file_result in scan_results.get('files', {}).values():
            for vuln in file_result.get('vulnerabilities', []):
                severity = vuln.get('severity', 'medium')
                if severity == 'critical':
                    critical_count += 1
                elif severity == 'high':
                    high_count += 1
                elif severity == 'medium':
                    medium_count += 1
                elif severity == 'low':
                    low_count += 1

        # Choose emoji and color based on results
        if critical_count > 0:
            emoji = '🚨'
            color = '#d00000'
        elif high_count > 0:
            emoji = '⚠️'
            color = '#ff6b35'
        elif total_vulns > 0:
            emoji = '⚡'
            color = '#ffa500'
        else:
            emoji = '✅'
            color = '#00b300'

        # Build vulnerability breakdown
        vuln_breakdown = []
        if critical_count > 0:
            vuln_breakdown.append(f'🔴 *Critical:* {critical_count}')
        if high_count > 0:
            vuln_breakdown.append(f'🟠 *High:* {high_count}')
        if medium_count > 0:
            vuln_breakdown.append(f'🟡 *Medium:* {medium_count}')
        if low_count > 0:
            vuln_breakdown.append(f'🟢 *Low:* {low_count}')

        breakdown_text = '\n'.join(vuln_breakdown) if vuln_breakdown else '_No vulnerabilities found_'

        # Build message
        mention = ''
        if critical_count > 0 and self.mention_on_critical:
            mention = '<!channel> '

        text = f'{mention}{emoji} Security scan completed'

        payload = {
            'text': text,
            'attachments': [
                {
                    'color': color,
                    'blocks': [
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': f'{emoji} *Security Scan Complete*'
                            }
                        },
                        {
                            'type': 'section',
                            'fields': [
                                {
                                    'type': 'mrkdwn',
                                    'text': f'*Files Scanned:*\n{stats.get("total_files", 0)}'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': f'*Total Issues:*\n{total_vulns}'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': f'*Cache Hit Rate:*\n{stats.get("cache_hit_rate", 0):.1%}'
                                },
                                {
                                    'type': 'mrkdwn',
                                    'text': f'*Scan Duration:*\n{stats.get("total_analysis_time", 0):.1f}s'
                                }
                            ]
                        },
                        {
                            'type': 'section',
                            'text': {
                                'type': 'mrkdwn',
                                'text': f'*Vulnerability Breakdown:*\n{breakdown_text}'
                            }
                        }
                    ]
                }
            ]
        }

        self._send_to_slack(payload)

    def _send_to_slack(self, payload: Dict[str, Any]):
        """Send payload to Slack webhook."""
        try:
            import requests
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )

            if response.status_code != 200:
                print(f"Slack notification failed: {response.status_code} {response.text}")

        except ImportError:
            print("Warning: requests library not installed, cannot send Slack notifications")
        except Exception as e:
            print(f"Error sending Slack notification: {e}")
