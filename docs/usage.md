# Usage Guide

## CLI Commands

### Scan

Scan a system for security issues:

```bash
claysecaudit scan [OPTIONS]
```

Options:
- `--hostname HOSTNAME`: Target hostname or IP (default: localhost)
- `--save-report`: Generate JSON and PDF reports (default: true)
- `--verbose`: Detailed output (default: false)

Examples:

```bash
# Scan localhost with report
claysecaudit scan --save-report

# Scan remote server
claysecaudit scan --hostname 192.168.1.100

# Verbose output for debugging
claysecaudit scan --hostname myserver.com --verbose

# Scan without saving reports
claysecaudit scan --hostname localhost --no-save-report
```

### Fix

Apply security fixes to detected issues:

```bash
claysecaudit fix [OPTIONS]
```

Options:
- `--finding-id ID`: Fix specific finding (default: all)
- `--auto-confirm`: Skip confirmation prompt (default: false)
- `--dry-run`: Preview fixes without applying (default: true)

Examples:

```bash
# Preview fixes (dry-run)
claysecaudit fix --dry-run

# Apply all fixes with confirmation
claysecaudit fix --auto-confirm

# Fix specific finding
claysecaudit fix --finding-id ssh_root_login --auto-confirm

# Review changes before applying
claysecaudit fix --dry-run
# Review output...
claysecaudit fix --auto-confirm
```

### Report

Generate security audit reports:

```bash
claysecaudit report [OPTIONS]
```

Options:
- `--audit-id ID`: Audit ID (uses last scan if not specified)
- `--format FORMAT`: Report format (json, pdf, or both) (default: json)

Examples:

```bash
# Generate JSON report
claysecaudit report --format json

# Generate PDF report
claysecaudit report --format pdf

# Generate both reports
claysecaudit report --format both

# Generate report for specific audit
claysecaudit report --audit-id abc123def456 --format both
```

### Score

Display the current security score:

```bash
claysecaudit score
```

### Version

Show version information:

```bash
claysecaudit version
```

## Web Dashboard

Start the web API server:

```bash
python -m uvicorn src.dashboard.api:app --host 0.0.0.0 --port 8000
```

Access the dashboard at: `http://localhost:8000`

### API Endpoints

#### Health Check
```bash
curl http://localhost:8000/health
```

#### Start Scan
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"hostname": "localhost", "scanners": ["ssh", "ports"]}'
```

#### Check Scan Status
```bash
curl http://localhost:8000/scan/abc123
```

#### Get Real-time Logs
```bash
# WebSocket connection for real-time logs
wscat -c ws://localhost:8000/ws/scan/abc123
```

#### Generate Report
```bash
curl http://localhost:8000/report/abc123?format=json > report.json
```

#### Apply Fix
```bash
curl -X POST http://localhost:8000/fix/ssh_root_login \
  -H "Content-Type: application/json" \
  -d '{"dry_run": true}'
```

## Python API

Use Clay Sec Audit programmatically:

```python
from src.scanner.ssh import SSHAuditor
from src.scanner.ports import PortScanner
from src.scanner.nginx import NginxAuditor

# SSH Security Audit
ssh_auditor = SSHAuditor("myserver.com")
ssh_results = ssh_auditor.scan()
print(ssh_results)

# Port Scanning
port_scanner = PortScanner("myserver.com")
port_results = port_scanner.scan()
print(port_results)

# Nginx Configuration Audit
nginx_auditor = NginxAuditor("myserver.com")
nginx_results = nginx_auditor.scan()
print(nginx_results)

# Access findings
for finding in ssh_auditor.findings:
    print(f"{finding.severity.upper()}: {finding.title}")
    print(f"  Description: {finding.description}")
    print(f"  Remediation: {finding.remediation}")
```

### Using the Fix Engine

```python
from src.fix_engine.ssh_fix import SSHFixer
from src.fix_engine.rollback import RollbackManager

# Create fixer and rollback manager
fixer = SSHFixer()
rm = RollbackManager()

# Create a transaction
tx = rm.create_transaction("my_fix_transaction")

# Apply fix
success, message = fixer.fix_root_login(tx)

if not success:
    # Rollback if fix failed
    rm.rollback_transaction("my_fix_transaction")
else:
    # Commit transaction
    rm.commit_transaction("my_fix_transaction")
```

### Generating Reports

```python
from src.scanner.ssh import SSHAuditor
from src.reports.json_export import JSONReporter
from src.reports.pdf_generator import PDFReporter

# Run scan
auditor = SSHAuditor("localhost")
results = auditor.scan()

# Generate JSON report
json_reporter = JSONReporter()
json_file = json_reporter.generate_report(
    {"ssh_auditor": results},
    overall_score=75.5,
    audit_id="audit_123"
)
print(f"Report saved to: {json_file}")

# Generate PDF report
pdf_reporter = PDFReporter()
pdf_file = pdf_reporter.generate_report(
    {"ssh_auditor": results},
    overall_score=75.5,
    audit_id="audit_123"
)
print(f"Report saved to: {pdf_file}")
```

## Workflow Examples

### Example 1: Quick Security Check

```bash
# Run scan
sudo claysecaudit scan --save-report

# View results
claysecaudit score

# Check report
cat /var/lib/clay-sec-audit/reports/report_*.json | jq .
```

### Example 2: Identify and Fix SSH Issues

```bash
# Scan system
sudo claysecaudit scan --hostname myserver.com

# Preview SSH fixes
claysecaudit fix --dry-run

# Review the output carefully...

# Apply fixes
sudo claysecaudit fix --auto-confirm

# Verify fixes
claysecaudit score
```

### Example 3: Continuous Monitoring

```bash
# Schedule daily scans with cron
cat > /tmp/daily_audit.sh << 'EOF'
#!/bin/bash
sudo claysecaudit scan --save-report
cp /var/lib/clay-sec-audit/reports/* /path/to/archive/
EOF

chmod +x /tmp/daily_audit.sh

# Add to crontab
crontab -e
# Add line: 0 2 * * * /tmp/daily_audit.sh
```

### Example 4: Automated Remediation

```bash
#!/bin/bash

HOSTNAME=$1
REPORT_DIR="/var/lib/clay-sec-audit/reports"

# Run scan
sudo claysecaudit scan --hostname $HOSTNAME --save-report

# Auto-apply all fixes
sudo claysecaudit fix --auto-confirm

# Generate final report
claysecaudit report --format both

# Send report via email
REPORT=$(ls -t $REPORT_DIR/*.json | head -1)
mail -s "Security Audit Report" admin@example.com < $REPORT
```

## Best Practices

### 1. Always Use Dry-Run First

```bash
# Preview what will be changed
sudo claysecaudit fix --dry-run

# Review carefully
# Then apply
sudo claysecaudit fix --auto-confirm
```

### 2. Backup Before Fixing

The tool automatically creates backups, but also:

```bash
# Manual backup of important files
sudo tar czf /backup/etc_backup_$(date +%s).tar.gz /etc

# Then apply fixes
sudo claysecaudit fix --auto-confirm
```

### 3. Schedule Regular Scans

```bash
# Create scan script
cat > /usr/local/bin/security-audit << 'EOF'
#!/bin/bash
claysecaudit scan --save-report --verbose
EOF

chmod +x /usr/local/bin/security-audit

# Schedule weekly
echo "0 0 * * 0 /usr/local/bin/security-audit" | sudo tee -a /etc/crontab
```

### 4. Monitor Specific Scanners

```bash
# Run only specific scanners
claysecaudit scan --hostname localhost

# Then fix specific issues
claysecaudit fix --finding-id ssh_root_login --auto-confirm
```

### 5. Document All Changes

```bash
# Keep audit trail
sudo claysecaudit scan --save-report --verbose > /var/log/clay-audit.log

# Archive reports
mkdir -p /var/lib/clay-sec-audit/archive
cp /var/lib/clay-sec-audit/reports/* /var/lib/clay-sec-audit/archive/
```

## Troubleshooting

### Permission Errors

```bash
# Run with sudo
sudo claysecaudit scan

# Or configure passwordless sudo for specific command
echo "$(whoami) ALL=(ALL) NOPASSWD: /usr/local/bin/claysecaudit" | sudo tee /etc/sudoers.d/clay
```

### Scan Takes Too Long

```bash
# Use verbose mode to see progress
claysecaudit scan --verbose

# Run specific scanner only
claysecaudit scan --hostname localhost  # Then check source code to run single scanner
```

### Fix Fails

```bash
# Check detailed error logs
sudo claysecaudit fix --verbose

# Rollback manually if needed
cat /var/lib/clay-sec-audit/transactions/*.json
# Review and apply rollback if needed
```

### Services Don't Start After Fix

```bash
# Check backup
ls /var/lib/clay-sec-audit/backups/

# Manually restore if needed
sudo cp /var/lib/clay-sec-audit/backups/config.bak /etc/path/to/config

# Restart service
sudo systemctl restart service_name
```

## Advanced Configuration

See [architecture.md](architecture.md) for system design and [API.md](API.md) for API documentation.
