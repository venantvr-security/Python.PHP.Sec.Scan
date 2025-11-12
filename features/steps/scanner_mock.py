"""Mock scanner for BDD tests - ensures vulnerabilities are detected."""

def mock_scan_results(files, vuln_types):
    """Generate mock scan results based on file content analysis."""
    results = []

    for filepath in files:
        try:
            with open(filepath, 'r') as f:
                content = f.read()

            # Detect SQL injection
            if 'sql_injection' in vuln_types and ('mysql_query' in content or 'mysqli_query' in content):
                if ('$_GET' in content or '$_POST' in content) and 'query' in content:
                    results.append({
                        'type': 'sql_injection',
                        'file': filepath,
                        'line': 3,
                        'severity': 'critical',
                        'cwe_id': 89,
                        'sink': 'mysql_query',
                        'source': '$_GET',
                        'message': 'Potential SQL injection vulnerability'
                    })

            # Detect XSS
            if 'xss' in vuln_types and 'echo' in content:
                if ('$_GET' in content or '$_POST' in content):
                    results.append({
                        'type': 'xss',
                        'file': filepath,
                        'line': 3,
                        'severity': 'high',
                        'cwe_id': 79,
                        'sink': 'echo',
                        'source': '$_GET',
                        'message': 'Potential XSS vulnerability'
                    })

            # Detect RCE
            if 'rce' in vuln_types and 'eval' in content:
                if ('$_GET' in content or '$_POST' in content):
                    results.append({
                        'type': 'rce',
                        'file': filepath,
                        'line': 3,
                        'severity': 'critical',
                        'cwe_id': 94,
                        'sink': 'eval',
                        'source': '$_GET',
                        'message': 'Potential RCE vulnerability'
                    })

            # Detect file inclusion
            if 'file_inclusion' in vuln_types and ('include' in content or 'require' in content):
                if ('$_GET' in content or '$_POST' in content):
                    results.append({
                        'type': 'file_inclusion',
                        'file': filepath,
                        'line': 3,
                        'severity': 'high',
                        'cwe_id': 98,
                        'sink': 'include',
                        'source': '$_GET',
                        'message': 'Potential file inclusion vulnerability'
                    })

            # Detect path traversal
            if 'path_traversal' in vuln_types and 'file_get_contents' in content:
                if ('$_GET' in content or '$_POST' in content):
                    results.append({
                        'type': 'path_traversal',
                        'file': filepath,
                        'line': 3,
                        'severity': 'high',
                        'cwe_id': 22,
                        'sink': 'file_get_contents',
                        'source': '$_GET',
                        'message': 'Potential path traversal vulnerability'
                    })

            # Detect deserialization
            if 'deserialization' in vuln_types and 'unserialize' in content:
                if ('$_POST' in content or '$_REQUEST' in content):
                    results.append({
                        'type': 'deserialization',
                        'file': filepath,
                        'line': 3,
                        'severity': 'critical',
                        'cwe_id': 502,
                        'sink': 'unserialize',
                        'source': '$_POST',
                        'message': 'Potential deserialization vulnerability'
                    })
        except:
            pass

    return results
