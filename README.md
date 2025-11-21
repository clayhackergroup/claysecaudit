# Clay Sec Audit

A comprehensive open-source Linux security auditor and auto-fixer that scans servers for misconfigurations, detects risks, and safely applies fixes with rollback capabilities.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

## Features

### 🔍 Security Scanning
- **Port Security**: Scan for open ports and risky services (Redis, MongoDB, MySQL, etc.)
- **SSH Hardening**: Detect SSH misconfigurations (root login, password auth, weak ciphers)
- **Web Server Audit**: Check Nginx and Apache for security headers, weak SSL/TLS, directory listing
- **Database Security**: Scan MySQL, PostgreSQL, MongoDB, Redis, and CouchDB configurations
- **File Permissions**: Detect world-writable files, exposed private keys, weak permissions
- **API Security**: Check CORS misconfigurations, debug endpoints, exposed documentation

### 🔧 Automated Fixing
- **Backup & Rollback**: Automatic backup before any changes with safe rollback capability
- **Configuration Hardening**: SSH, Nginx, Apache, database configurations
- **Permission Fixes**: Correct file permissions, protect private keys
- **Service Management**: Test configurations before and after changes
- **Transaction Logging**: Track all fixes for audit purposes

### 📊 Reporting
- **JSON Reports**: Machine-readable scan results for integration
- **PDF Reports**: Professional security audit reports
- **Security Scoring**: Quantified security posture (0-100)
- **Detailed Findings**: Severity classification, remediation steps

### 💻 Interfaces
- **CLI Tool**: Command-line interface for automated auditing
- **Web Dashboard**: FastAPI backend with real-time scan progress
- **REST API**: Full API for integration with other tools
- **WebSocket Support**: Real-time log streaming

## Installation

### Prerequisites
- Linux system (Ubuntu 18.04+, CentOS 7+, Debian 10+)
- Python 3.8 or higher
- Root or sudo access for scanning and fixing

### Quick Install

```bash
# Clone the repository
git clone https://github.com/clay/clay-sec-audit.git
cd clay-sec-audit

# Install dependencies
pip install -r requirements.txt

# Install as command-line tool
pip install -e .

# Verify installation
claysecaudit version
```

## Usage

### CLI Usage

#### Run a security scan
```bash
claysecaudit scan --hostname localhost --save-report
```

Options:
- `--hostname`: Target hostname (default: localhost)
- `--save-report`: Generate JSON and PDF reports (default: true)
- `--verbose`: Detailed output

#### View security score
```bash
claysecaudit score
```

#### Generate reports
```bash
claysecaudit report --format json
claysecaudit report --format pdf
claysecaudit report --format both
```

#### Apply security fixes
```bash
# Preview what would be fixed (dry-run)
claysecaudit fix --dry-run

# Apply fixes with confirmation
claysecaudit fix --auto-confirm
```

### Web Dashboard

Start the FastAPI server:
```bash
python -m uvicorn src.dashboard.api:app --host 0.0.0.0 --port 8000
```

Access at `http://localhost:8000`

API endpoints:
- `GET /health` - Health check
- `POST /scan` - Start a security scan
- `GET /scan/{audit_id}` - Get scan status
- `POST /fix/{finding_id}` - Apply a fix
- `GET /report/{audit_id}` - Generate report
- `GET /logs/{audit_id}` - Get scan logs
- `WS /ws/scan/{audit_id}` - Real-time scan logs

### Python API

```python
from src.scanner.ssh import SSHAuditor
from src.scanner.ports import PortScanner

# Scan for SSH issues
ssh_auditor = SSHAuditor("myserver.com")
results = ssh_auditor.scan()

# Scan for open ports
port_scanner = PortScanner("myserver.com")
results = port_scanner.scan()

print(results)
```

## Architecture

```
clay-sec-audit/
├── src/
│   ├── scanner/           # Security scanning modules
│   │   ├── ports.py       # Port and service scanning
│   │   ├── ssh.py         # SSH configuration auditing
│   │   ├── nginx.py       # Nginx security audit
│   │   ├── apache.py      # Apache security audit
│   │   ├── db.py          # Database exposure scanning
│   │   ├── filesystem.py  # File permission auditing
│   │   └── api_scanner.py # API security checks
│   │
│   ├── fix_engine/        # Automated fix modules
│   │   ├── backup.py      # Backup management
│   │   ├── rollback.py    # Rollback system
│   │   ├── ssh_fix.py     # SSH hardening
│   │   ├── nginx_fix.py   # Nginx hardening
│   │   ├── apache_fix.py  # Apache hardening
│   │   ├── db_fix.py      # Database hardening
│   │   └── permissions_fix.py # Permission fixes
│   │
│   ├── reports/           # Reporting system
│   │   ├── json_export.py # JSON report generation
│   │   └── pdf_generator.py # PDF report generation
│   │
│   ├── cli/               # Command-line interface
│   │   └── cli.py         # Typer CLI implementation
│   │
│   └── dashboard/         # Web dashboard
│       └── api.py         # FastAPI backend
```

## Security Checks

### Port Scanner
- Detects services on common ports
- Identifies risky service exposure (Redis, MongoDB, MySQL)
- Checks if services bind to 0.0.0.0

### SSH Auditor
- Root login enabled
- Password authentication enabled
- Weak cipher suites
- Weak key exchange algorithms
- fail2ban status
- X11 forwarding enabled
- Empty password support
- Non-standard port usage

### Web Server Auditor
- Missing security headers (X-Content-Type-Options, X-Frame-Options, HSTS)
- Weak SSL/TLS versions
- Server version exposure
- Directory listing enabled
- Weak cipher suites

### Database Scanner
- MySQL/PostgreSQL/MongoDB/Redis/CouchDB exposure
- Weak bind configuration
- Missing authentication
- Anonymous access
- Unencrypted connections

### Filesystem Auditor
- World-writable files and directories
- Exposed private keys (improper permissions)
- Weak permissions on sensitive files (/etc/shadow, /etc/passwd)
- SUID binary count
- Temporary directory permissions

### API Security Scanner
- CORS misconfigurations (wildcard origins)
- Debug endpoints
- Exposed API documentation
- Missing authentication headers

## Severity Levels

- **CRITICAL**: Immediate security breach risk
- **HIGH**: Significant security vulnerability
- **MEDIUM**: Important security issue
- **LOW**: Security best practice recommendation

## Fix Engine

### Backup & Rollback
All fixes include automatic backup:
1. Backup original file
2. Apply fix
3. Validate configuration
4. Test service if applicable
5. Rollback automatically if test fails

Example:
```python
from src.fix_engine.ssh_fix import SSHFixer
from src.fix_engine.rollback import RollbackManager

fixer = SSHFixer()
rm = RollbackManager()
transaction = rm.create_transaction("fix_123")

success, message = fixer.fix_root_login(transaction)
if not success:
    rm.rollback_transaction("fix_123")
```

## Reporting

### JSON Report Format
```json
{
  "audit_id": "abc123",
  "timestamp": "2024-01-15T10:30:00",
  "security_score": 72.5,
  "summary": {
    "total_findings": 12,
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 3
  },
  "scanners": {
    "ssh_auditor": {
      "findings": [...],
      "total_findings": 2
    }
  }
}
```

### PDF Report
Professional audit report with:
- Executive summary
- Security score
- Detailed findings by category
- Remediation recommendations
- Audit timestamp

## Testing

Run test suite:
```bash
pytest tests/
```

Test specific module:
```bash
pytest tests/test_ssh_auditor.py -v
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Roadmap

- [x] Core scanner implementations
- [x] Automated fix engine with rollback
- [x] CLI interface
- [x] JSON/PDF reporting
- [x] FastAPI backend
- [ ] React web dashboard
- [ ] Kubernetes security audit
- [ ] Container image scanning
- [ ] Cloud provider integrations (AWS, Azure, GCP)
- [ ] Machine learning for threat detection
- [ ] Mobile app

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/clay/clay-sec-audit/issues)
- **Security**: [SECURITY.md](SECURITY.md)

## License

This project is licensed under the GNU General Public License v3.0 - see [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is designed to help identify security misconfigurations. Always:
- Test in non-production environments first
- Backup systems before applying fixes
- Review changes before applying them
- Understand the impact of security configurations on your applications
- Use in compliance with applicable laws and regulations

## Credits

Built with ❤️ by the Clay Security Team

---

**Security Notice**: If you discover a security vulnerability, please report it responsibly to developers.claygroup@gmail.com instead of using the issue tracker.
