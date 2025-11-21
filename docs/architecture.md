# Architecture Guide

## System Overview

Clay Sec Audit is built with a modular, layered architecture:

```
┌─────────────────────────────────────────────────────────┐
│              User Interfaces                             │
├──────────────┬──────────────┬──────────────┬─────────────┤
│   CLI Tool   │  Web API     │  Dashboard   │  REST API   │
└──────────────┴──────────────┴──────────────┴─────────────┘
                      │
┌─────────────────────────────────────────────────────────┐
│           Core Audit Engine                              │
├─────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Scanners     │  │ Fix Engine   │  │ Reports      │  │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤  │
│  │ • SSH        │  │ • Backup     │  │ • JSON       │  │
│  │ • Ports      │  │ • Rollback   │  │ • PDF        │  │
│  │ • Web Svr    │  │ • Validators │  │ • Score      │  │
│  │ • Database   │  │ • Apply Fixer│  │              │  │
│  │ • Filesystem │  │              │  │              │  │
│  │ • API        │  │              │  │              │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                      │
┌─────────────────────────────────────────────────────────┐
│           Target Systems                                 │
├──────────────┬──────────────┬──────────────┬─────────────┤
│ Linux Server │  SSH Config  │   Services   │  Databases  │
└──────────────┴──────────────┴──────────────┴─────────────┘
```

## Component Architecture

### 1. Scanner Modules (`src/scanner/`)

Each scanner module is independent and follows the `ScannerBase` pattern:

```python
class ScannerBase:
    def scan() -> Dict[str, Any]
    def add_finding(finding: Finding)
    def get_overall_score() -> float
    def get_findings_by_severity() -> Dict
```

**Scanners:**
- `ports.py`: Open port detection, service identification
- `ssh.py`: SSH configuration analysis
- `nginx.py`: Nginx security audit
- `apache.py`: Apache security audit
- `filesystem.py`: File permission checks
- `db.py`: Database exposure scanning
- `api_scanner.py`: API security checks

### 2. Fix Engine (`src/fix_engine/`)

Implements safe fix application with backup and rollback:

```
┌────────────────────────────────────┐
│  User Requests Fix                  │
└────────────────────┬───────────────┘
                     │
┌────────────────────▼───────────────┐
│  Create Transaction                 │
└────────────────────┬───────────────┘
                     │
┌────────────────────▼───────────────┐
│  Backup Original File               │
│  (BackupManager)                    │
└────────────────────┬───────────────┘
                     │
┌────────────────────▼───────────────┐
│  Apply Fix                          │
│  (Specific Fixer: SSH, Nginx, etc) │
└────────────────────┬───────────────┘
                     │
┌────────────────────▼───────────────┐
│  Validate Configuration             │
│  (Service-specific tests)           │
└────────────────────┬───────────────┘
                     │
              ┌──────┴──────┐
              │             │
         ✓ Pass         ✗ Fail
              │             │
              │    ┌────────▼─────────┐
              │    │ Rollback File    │
              │    │ (from backup)    │
              │    └──────────────────┘
              │
┌─────────────▼───────────────────────┐
│  Commit Transaction                  │
│  (RollbackManager)                   │
└──────────────────────────────────────┘
```

**Components:**
- `backup.py`: File backup management
- `rollback.py`: Transaction tracking and rollback
- `*_fix.py`: Service-specific fixers

### 3. Reporting System (`src/reports/`)

Generates machine-readable and human-readable reports:

```
Scan Results
    │
    ├─► JSONReporter
    │       │
    │       └─► report_*.json
    │
    └─► PDFReporter
            │
            └─► report_*.pdf
```

### 4. CLI Interface (`src/cli/`)

Command-line interface using Typer:

```
claysecaudit
    ├─ scan      → Run security scan
    ├─ fix       → Apply fixes
    ├─ report    → Generate reports
    ├─ score     → Show security score
    └─ version   → Show version
```

### 5. Web Dashboard (`src/dashboard/`)

FastAPI backend for programmatic access:

```
HTTP/REST Clients
    │
    ├─► /health          ──► Health check
    ├─► POST /scan       ──► Start scan
    ├─► GET /scan/:id    ──► Get status
    ├─► POST /fix/:id    ──► Apply fix
    ├─► GET /report/:id  ──► Generate report
    ├─► GET /logs/:id    ──► Fetch logs
    └─► WS /ws/scan/:id  ──► Real-time logs
```

## Data Flow

### Scan Process

1. **Initialization**
   - User initiates scan via CLI/API
   - Unique audit ID generated
   - Scan configuration validated

2. **Scanner Execution**
   - Each scanner module runs independently
   - System commands executed (ss, grep, curl, etc.)
   - Findings collected in Finding objects

3. **Analysis**
   - Findings grouped by severity
   - Overall security score calculated
   - Results aggregated

4. **Reporting**
   - JSON report generated for machine parsing
   - PDF report generated for human review
   - Results cached in memory

### Fix Process

1. **User Confirmation**
   - Dry-run preview of changes
   - User confirms fix application
   - Transaction created

2. **Pre-Fix**
   - Original file backed up
   - Backup path recorded in transaction

3. **Fix Application**
   - Configuration updated
   - New settings applied

4. **Validation**
   - Service configuration tested
   - Service restarted if applicable
   - Results verified

5. **Post-Fix**
   - Transaction marked committed
   - Backup retained for audit trail
   - Logs recorded

6. **Rollback (if needed)**
   - Original file restored from backup
   - Service restarted
   - Transaction marked rolled_back

## File Structure

```
clay-sec-audit/
├── src/
│   ├── __init__.py           # Package initialization
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── utils.py          # ScannerBase, Finding classes
│   │   ├── ports.py          # Port scanning
│   │   ├── ssh.py            # SSH auditing
│   │   ├── nginx.py          # Nginx auditing
│   │   ├── apache.py         # Apache auditing
│   │   ├── filesystem.py     # File permission auditing
│   │   ├── db.py             # Database scanning
│   │   └── api_scanner.py    # API security
│   ├── fix_engine/
│   │   ├── __init__.py
│   │   ├── backup.py         # Backup management
│   │   ├── rollback.py       # Transaction/rollback mgmt
│   │   ├── ssh_fix.py        # SSH fixes
│   │   ├── nginx_fix.py      # Nginx fixes
│   │   ├── apache_fix.py     # Apache fixes
│   │   ├── db_fix.py         # Database fixes
│   │   └── permissions_fix.py # Permission fixes
│   ├── reports/
│   │   ├── __init__.py
│   │   ├── json_export.py    # JSON report generation
│   │   └── pdf_generator.py  # PDF report generation
│   ├── cli/
│   │   ├── __init__.py
│   │   └── cli.py            # CLI implementation
│   └── dashboard/
│       ├── __init__.py
│       └── api.py            # FastAPI backend
├── tests/
│   ├── __init__.py
│   ├── test_scanners.py      # Scanner tests
│   ├── test_fix_engine.py    # Fix engine tests
│   └── test_reporting.py     # Report generation tests
├── docs/
│   ├── installation.md       # Installation guide
│   ├── usage.md             # Usage guide
│   ├── architecture.md      # This file
│   └── API.md               # API documentation
├── requirements.txt          # Python dependencies
├── setup.py                 # Package setup
├── LICENSE                  # GPL-3.0 license
└── README.md                # Project README
```

## Security Considerations

### Code Execution
- All system commands executed via `subprocess` with timeout
- Commands properly quoted to prevent injection
- Return codes and stderr checked

### File Permissions
- Backup directories created with mode 0o700
- Sensitive files protected from world-readable access
- Transaction logs secured

### Configuration Validation
- All config changes validated before application
- Services tested after configuration changes
- Automatic rollback on validation failure

### Audit Trail
- All operations logged with timestamp
- Backup files retained for rollback capability
- Transaction history maintained

## Scalability

### Current Limitations
- Scans executed sequentially per target
- Maximum ~100 findings per scanner
- Scan results cached in memory

### Future Improvements
- Distributed scanning (multiple targets)
- Result persistence in database
- Async/concurrent scanner execution
- API caching and pagination

## Extension Points

### Adding New Scanners

1. Create `src/scanner/new_check.py`:
```python
from src.scanner.utils import ScannerBase, Finding

class NewAuditor(ScannerBase):
    def scan(self):
        # Implementation
        pass
```

2. Register in CLI (`src/cli/cli.py`)

### Adding New Fixers

1. Create `src/fix_engine/new_fix.py`:
```python
from src.fix_engine.backup import BackupManager

class NewFixer:
    def fix_something(self, transaction):
        # Implementation with backup/rollback
        pass
```

2. Register in CLI fix command

### Custom Reports

1. Create `src/reports/custom_report.py`:
```python
class CustomReporter:
    def generate_report(self, scan_results, score, audit_id):
        # Implementation
        pass
```

## Integration Points

### External Systems
- Jenkins/GitLab CI for automated scanning
- Slack for notifications
- Email for report delivery
- Prometheus for metrics

### Example CI Integration:
```yaml
# .gitlab-ci.yml
security_audit:
  script:
    - claysecaudit scan --save-report
    - claysecaudit fix --auto-confirm
  artifacts:
    paths:
      - /var/lib/clay-sec-audit/reports/
```

## Performance

### Typical Scan Times
- SSH Auditor: ~1 second
- Port Scanner: ~2-5 seconds
- Filesystem Auditor: ~3-10 seconds
- Web Server Auditors: ~1-2 seconds
- Database Scanner: ~2 seconds
- API Scanner: ~2 seconds
- **Total**: 12-25 seconds

### Memory Usage
- Baseline: ~50 MB
- Per scan result: ~100 KB
- Typical full scan: ~100-200 MB

## Deployment

### Standalone
```bash
pip install clay-sec-audit
claysecaudit scan
```

### Container
```dockerfile
FROM python:3.10-slim
RUN pip install clay-sec-audit
CMD ["claysecaudit"]
```

### Kubernetes
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: clay-sec-audit
spec:
  containers:
  - name: audit
    image: clay-sec-audit:latest
    volumeMounts:
    - name: config
      mountPath: /etc
      readOnly: true
```

## Monitoring

### Metrics to Track
- Scan success rate
- Average scan time
- Fix application success rate
- Security score trends
- Critical finding count

### Example Prometheus Metrics:
```
clay_sec_audit_scan_duration_seconds
clay_sec_audit_findings_total
clay_sec_audit_security_score
clay_sec_audit_fix_success_total
```

For detailed API documentation, see [API.md](API.md).
