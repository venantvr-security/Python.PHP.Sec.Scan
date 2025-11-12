# PHP Security Scanner - Architecture

## Overview

The PHP Security Scanner is a production-ready static analysis tool designed for scalability, extensibility, and accuracy. It uses tree-sitter for AST parsing and
implements taint analysis to detect security vulnerabilities in PHP code.

## Architecture Diagram

**Layer 1: Entry Points**

- CLI (`cli_v2.py`) - Command-line interface with full feature access
- REST API (`api/main.py`) - FastAPI service for integration
- Batch Scripts (`scripts/batch_scan.py`) - Multi-project scanning
- Custom Plugins (`plugins/custom_*.py`) - Extensible hooks

**Layer 2: Core Scanner** (`workers/parallel_scanner.py`)

- Multi-threaded file scanning (configurable workers)
- Plugin lifecycle management (hooks at each stage)
- Real-time progress tracking with callbacks
- Scan context propagation

**Layer 3: Processing Components**

*Analysis Engine*
- `analysis/taint_tracker.py` - Intra-procedural taint analysis
- `analysis/call_graph.py` - Function relationship mapping
- `analysis/interprocedural.py` - Cross-function propagation

*Caching Layer*
- `cache/ast_cache.py` - Disk-based persistent cache
- `cache/redis_cache.py` - Optional distributed L2 cache

*Plugin System*
- WordPress plugin - Framework-specific checks
- Performance Monitor - Scan optimization
- Notification plugins - Slack, email alerts
- Policy Enforcement - CI/CD thresholds

**Layer 4: Storage & Export**

- Database (`db/models.py`) - SQLite/PostgreSQL scan history
- Suppressions (`suppressions/manager.py`) - Fingerprint-based filtering
- Exporters - SARIF, JSON, Prometheus formats
- Reports - HTML, Markdown generation

## Component Details

### 1. Analysis Engine

#### Taint Tracker (`analysis/taint_tracker.py`)

- **Purpose**: Intra-procedural taint analysis
- **Method**: AST traversal with dataflow tracking
- **Capabilities**:
    - Source identification (`$_GET`, `$_POST`, etc.)
    - Sink detection (function calls, echo statements)
    - Sanitizer recognition
    - Variable assignment tracking
    - Function parameter propagation

**Algorithm**:

```text
1. Parse PHP file to AST (tree-sitter)
2. Initialize tainted_vars set
3. Traverse AST depth-first:
   a. Mark sources as tainted
   b. Track variable assignments
   c. Check sinks for tainted data
   d. Apply sanitizers (remove from tainted set)
4. Report vulnerabilities
```

#### Call Graph Builder (`analysis/call_graph.py`)

- **Purpose**: Inter-procedural analysis infrastructure
- **Features**:
    - Function definition extraction
    - Call site identification
    - Include/require resolution
    - Parameter tracking

#### Interprocedural Analyzer (`analysis/interprocedural.py`)

- **Purpose**: Cross-function taint propagation
- **Status**: Functional for basic cases
- **Limitations**: String concatenation, array tracking WIP

#### Worklist Algorithm (`analysis/worklist.py`)

- **Purpose**: Fixed-point iteration for dataflow
- **Status**: Infrastructure complete, full dataflow WIP
- **Approach**:
    - Iterative constraint solving
    - Function-level taint facts
    - Caller propagation

### 2. Caching Layer

#### AST Cache (`cache/ast_cache.py`)

- **Backend**: diskcache (SQLite-based)
- **Key**: SHA256 file hash
- **Value**: Parsed AST + analysis results
- **Performance**: 80%+ hit rate, 20x speedup

#### Redis Cache (`cache/redis_cache.py`)

- **Purpose**: Distributed caching for multi-server setups
- **Architecture**: L1 (disk) + L2 (Redis) hybrid
- **Use case**: CI/CD with multiple workers

### 3. Plugin System

#### Architecture

```python
# noinspection PyUnresolvedReferences
class ScannerPlugin(ABC):

    # noinspection PyMethodMayBeStatic,PyMethodParameters
    def on_scan_start(context):  # Before scan

        def on_file_scanned(file, results):  # After each file
            pass

        def on_scan_complete(results):  # After scan
            pass

        def on_vulnerability_found(vuln):  # Process/filter vuln
            pass
```

#### Built-in Plugins

1. **WordPress**: Detects WP projects, tracks hooks
2. **Performance**: Monitors scan performance
3. **Notification**: Webhook notifications
4. **Metrics Exporter**: Prometheus/JSON export
5. **Slack Notifier**: Rich Slack messages
6. **Security Policy**: CI/CD policy enforcement
7. **Custom Rules**: Organization-specific checks

### 4. Database Schema

**projects** table
- id, name, root_path, is_wordpress
- created_at, updated_at

**scans** table
- id, project_id, status, vuln_types
- started_at, completed_at, duration
- total_files, scanned_files, total_vulnerabilities

**vulnerabilities** table
- id, scan_id, vuln_type, severity
- filepath, line_number, column_number
- sink_function, tainted_variable
- is_suppressed, suppression_reason

**warnings** table
- id, scan_id, warning_type
- filepath, line_number, message

**files** table
- id, scan_id, filepath, file_hash
- analyzed, analysis_duration_ms
- vulnerabilities_count, warnings_count

### 5. API Layer

FastAPI endpoints:

- `GET /`: API info
- `GET /projects`: List projects
- `POST /scan`: Trigger scan (background task)
- `GET /scans/{id}`: Scan status
- `GET /vulnerabilities/{scan_id}`: List vulns
- `GET /export/{scan_id}/sarif`: Export SARIF
- `POST /suppressions/add`: Add suppression

Background tasks use ThreadPoolExecutor for non-blocking scans.

### 6. Rule Engine

#### DSL Format (YAML)

```yaml
- name: sql_injection
  sources:
    - pattern: "$_GET[*]"
  sinks:
    - node_type: function_call_expression
      function: mysqli_query
      args:
        - index: 1
          type: string
          contains: variable
      vuln: sql_injection
  filters:
    - function: mysqli_real_escape_string
      sanitizes: [ sql_injection ]
```

Supports:

- Pattern matching (wildcards)
- Node type matching
- Argument position checking
- Method calls (class::method)
- Multiple sources/sinks/filters per rule

### 7. Suppression System

#### Fingerprint-based

```python
# noinspection PyUnresolvedReferences
fingerprint = SHA256(vuln_type + file + line + sink)
```

Benefits:

- Survives code refactoring (if line unchanged)
- Unique identification
- Audit trail (reason, author, timestamp)

#### Pattern-based (Allowlist)

```yaml
- pattern:
    file_pattern: "vendor/.*"
    type: xss
  reason: "Third-party code"
```

Useful for:

- Bulk suppressions
- Directory-level exceptions
- Framework-specific false positives

## Data Flow

### Scan Workflow

```
1. User triggers scan (CLI/API)
2. Discover PHP files (glob *.php)
3. For each file (parallel):
   a. Compute hash
   b. Check cache
   c. If miss: parse AST
   d. Run taint analysis
   e. Apply rules
   f. Cache result
   g. Trigger plugin: on_file_scanned
4. Collect all results
5. Apply suppressions
6. Save to database
7. Export (SARIF, JSON, HTML)
8. Trigger plugin: on_scan_complete
```

### Performance Optimizations

- **Multi-threading**: 12 workers default (CPU-bound)
- **AST caching**: Disk-based, persistent across runs
- **Batch DB inserts**: 1000 records per transaction
- **Lazy loading**: Only load rules for requested vuln types
- **Node caching**: In-memory cache for AST traversal

## Scalability

### Horizontal Scaling

```yaml
# docker-compose.yml
services:
  api:
    replicas: 3
  worker:
    replicas: 10
  redis:
    replicas: 1
  postgres:
    replicas: 1 (or RDS)
```

### Performance Characteristics

| Files | Workers | Cache | Time | Throughput |
|-------|---------|-------|------|------------|
| 100   | 1       | No    | 30s  | 3 f/s      |
| 100   | 12      | No    | 3s   | 33 f/s     |
| 100   | 12      | Yes   | 1s   | 100 f/s    |
| 1000  | 12      | No    | 30s  | 33 f/s     |
| 1000  | 12      | Yes   | 5s   | 200 f/s    |

### Bottlenecks

1. **AST Parsing**: CPU-bound (tree-sitter)
2. **Database Writes**: I/O-bound (use batch inserts)
3. **Disk Cache**: Local only (use Redis for distributed)

## Extension Points

### 1. Custom Rules

Add to `config/rules.yaml` or `config/rules_wordpress.yaml`.

### 2. Custom Plugins

```python
# noinspection PyUnresolvedReferences
class MyPlugin(ScannerPlugin):

    def on_scan_start(self, context):
        pass

    # Initialization
    # noinspection PyMethodMayBeStatic
    def on_vulnerability_found(self, vuln):
        # Modify severity, add context
        return vuln
```

### 3. Custom Exporters

Implement `BaseExporter` interface:

```python
class CustomExporter:

    def export(self, vulnerabilities, output_file):
        # Custom format
        pass
```

### 4. Custom Sanitizers

Add to rules:

```yaml
filters:
  - function: my_sanitize
    sanitizes: [ xss, sql_injection ]
```

## Security Considerations

### False Positives

- Suppression system
- Manual review
- Sanitizer detection

### False Negatives

- Complex dataflow (e.g., array tracking)
- String operations (concat, substr)
- Magic methods (__toString, __call)
- Dynamic includes (eval, include $var)

### Recommendations

1. Run on every commit (CI/CD)
2. Set policy thresholds (0 critical)
3. Review suppressions monthly
4. Combine with dynamic testing

## Testing Strategy

### Unit Tests (70 tests)

- Taint tracker: 45 tests
- Database: 6 tests
- Cache: 6 tests
- Plugins: 12 tests

### Integration Tests (7 tests)

- Full pipeline
- Database storage
- Plugin lifecycle
- CLI invocation

### Performance Tests

- `benchmarks/benchmark_performance.py`
- Worker scaling
- Cache effectiveness

## Deployment

### Docker

```bash
docker-compose up -d
```

Services:

- API (port 8000)
- PostgreSQL (port 5432)
- Redis (port 6379)
- Worker (background)

### CI/CD (GitHub Actions)

```yaml
- Lint (ruff)
- Test (pytest)
- Benchmark (weekly)
- Docker build
- Deploy to prod
```

## Future Work

### Phase 3 (Advanced Analysis)

- [ ] Symbolic execution
- [ ] Abstract interpretation
- [ ] Alias analysis
- [ ] Object sensitivity

### Phase 4 (Intelligence)

- [ ] Machine learning for prioritization
- [ ] Historical analysis (trend detection)
- [ ] Auto-fix suggestions
- [ ] IDE integration (LSP)

### Phase 5 (Enterprise)

- [ ] Multi-tenant support
- [ ] RBAC (role-based access control)
- [ ] SSO integration
- [ ] Compliance reports (PCI-DSS, OWASP)

## References

- Tree-sitter: https://tree-sitter.github.io/
- SARIF: https://sarifweb.azurewebsites.net/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- FastAPI: https://fastapi.tiangolo.com/
