# Clay Sec Audit - Quick Start Guide

Get up and running with Clay Sec Audit in 5 minutes!

## Installation

```bash
# Clone the repository
git clone https://github.com/clay/clay-sec-audit.git
cd clay-sec-audit

# Install with pip
pip install -r requirements.txt
pip install -e .

# Verify installation
claysecaudit version
```

## Basic Usage

### 1. Run Your First Scan

```bash
# Scan your local system
sudo claysecaudit scan --save-report

# Output will show:
# Overall Security Score: 72.5/100
# Summary table with findings by severity
```

### 2. Check Security Score

```bash
claysecaudit score

# Shows your current security posture
```

### 3. Review Findings

```bash
# Check generated report
cat /var/lib/clay-sec-audit/reports/report_*.json | jq .

# Or view PDF
open /var/lib/clay-sec-audit/reports/report_*.pdf
```

### 4. Fix Issues

```bash
# Preview what will be fixed (dry-run)
sudo claysecaudit fix --dry-run

# Apply fixes
sudo claysecaudit fix --auto-confirm

# Check new score
claysecaudit score
```

## Web Dashboard

```bash
# Start API server
python -m uvicorn src.dashboard.api:app --host 0.0.0.0 --port 8000

# Access at http://localhost:8000
# Swagger docs at http://localhost:8000/docs
```

### Quick API Test

```bash
# Start a scan
AUDIT_ID=$(curl -s -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"hostname":"localhost"}' | jq -r .audit_id)

# Check status
curl http://localhost:8000/scan/$AUDIT_ID | jq .

# Get report when ready
curl http://localhost:8000/report/$AUDIT_ID?format=json > report.json
```

## Common Commands

```bash
# Scan specific system
sudo claysecaudit scan --hostname 192.168.1.100 --save-report

# Fix SSH issues only
sudo claysecaudit fix --finding-id ssh_root_login --auto-confirm

# Generate both JSON and PDF reports
claysecaudit report --format both

# Run verbose scan for debugging
sudo claysecaudit scan --verbose

# Schedule daily scans
echo "0 2 * * * /usr/local/bin/claysecaudit scan --save-report" | sudo tee -a /etc/crontab
```

## What It Checks

- ✅ SSH configuration (root login, password auth, weak ciphers)
- ✅ Open ports and exposed services (Redis, MongoDB, MySQL)
- ✅ Web servers (Nginx/Apache security headers, SSL/TLS)
- ✅ File permissions (world-writable files, private keys)
- ✅ Databases (exposure, authentication, binding)
- ✅ API security (CORS, debug endpoints, documentation)

## What It Fixes

- 🔧 SSH hardening (disable root login, password auth)
- 🔧 Web server security (add headers, disable directory listing)
- 🔧 File permissions (private keys, config files)
- 🔧 Database configuration (bind to localhost, enable auth)
- 🔧 Automatic backup + rollback on any fix

## Directory Structure

```
clay-sec-audit/
├── src/
│   ├── scanner/          # Security scanners
│   ├── fix_engine/       # Auto-fix with rollback
│   ├── reports/          # JSON/PDF reporting
│   ├── cli/              # Command-line interface
│   └── dashboard/        # Web API
├── docs/                 # Full documentation
├── tests/                # Test suite
└── README.md             # Full guide
```

## Next Steps

1. **Run Initial Scan**: `sudo claysecaudit scan --save-report`
2. **Review Findings**: Check generated JSON or PDF report
3. **Dry-Run Fixes**: `sudo claysecaudit fix --dry-run`
4. **Apply Fixes**: `sudo claysecaudit fix --auto-confirm`
5. **Schedule Regular Scans**: Add to crontab for automated auditing

## Documentation

- **[README.md](README.md)** - Full project overview
- **[Installation Guide](docs/installation.md)** - Detailed setup
- **[Usage Guide](docs/usage.md)** - All commands and examples
- **[Architecture](docs/architecture.md)** - System design
- **[API Docs](docs/API.md)** - REST API reference

## Troubleshooting

### Permission denied
```bash
# Run with sudo
sudo claysecaudit scan
```

### Command not found
```bash
# Reinstall
pip install -e .
```

### Need help?
```bash
# Show help
claysecaudit --help
claysecaudit scan --help
claysecaudit fix --help
```

## Key Features

🔒 **Safe by Design**
- Automatic backup before any changes
- Validation testing before & after fixes
- Transaction-based rollback system
- Complete audit trail

📊 **Comprehensive Scanning**
- 7 security scanner modules
- 50+ security checks
- Severity classification
- Detailed remediation steps

📈 **Easy Reporting**
- JSON for integration
- Professional PDF reports
- Security scoring (0-100)
- Trend tracking

🚀 **Multiple Interfaces**
- CLI for automation
- REST API for integration
- WebSocket for real-time logs
- Web dashboard

## Support

- **GitHub**: [github.com/clay/clay-sec-audit](https://github.com/clay/clay-sec-audit)
- **Issues**: Report bugs on GitHub Issues
- **Documentation**: See [docs/](docs/) folder

---

**Ready to secure your Linux systems?**

```bash
sudo claysecaudit scan
```

That's it! You're now auditing your system's security.
