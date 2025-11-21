# Installation Guide

## System Requirements

- **OS**: Linux (Ubuntu 18.04+, CentOS 7+, Debian 10+)
- **Python**: 3.8 or higher
- **Privileges**: Root or sudo access
- **Disk Space**: Minimum 1GB free space
- **Memory**: Minimum 512MB RAM

## Installation Methods

### Method 1: pip (Recommended)

```bash
# Install from PyPI
pip install clay-sec-audit

# Verify installation
claysecaudit version
```

### Method 2: From Source

```bash
# Clone repository
git clone https://github.com/clay/clay-sec-audit.git
cd clay-sec-audit

# Install dependencies
pip install -r requirements.txt

# Install as development package
pip install -e .

# Run tests
pytest tests/
```

### Method 3: Docker

```bash
# Build Docker image
docker build -t clay-sec-audit .

# Run container
docker run -it --rm \
  -v /etc:/etc:ro \
  -v /var:/var:ro \
  clay-sec-audit claysecaudit scan
```

## Dependency Installation

### Ubuntu/Debian

```bash
# Update package manager
sudo apt update

# Install Python development tools
sudo apt install python3 python3-pip python3-dev build-essential

# Install system dependencies
sudo apt install nmap sshpass curl

# Install Python dependencies
pip install -r requirements.txt
```

### CentOS/RHEL

```bash
# Install Python development tools
sudo yum install python3 python3-pip python3-devel gcc

# Install system dependencies
sudo yum install nmap sshpass curl

# Install Python dependencies
pip install -r requirements.txt
```

### Alpine Linux

```bash
apk add --no-cache python3 py3-pip gcc musl-dev nmap curl

pip install -r requirements.txt
```

## Virtual Environment Setup (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install package
pip install -e .
```

## Verification

```bash
# Check installation
claysecaudit --help

# Show version
claysecaudit version

# Run a test scan
sudo claysecaudit scan --hostname localhost --save-report
```

## Troubleshooting

### Permission Denied Errors

Clay Sec Audit requires root privileges to scan system configurations and apply fixes:

```bash
# Run with sudo
sudo claysecaudit scan

# Or configure sudoers for specific commands
echo "your_user ALL=(ALL) NOPASSWD: /usr/local/bin/claysecaudit" | sudo tee -a /etc/sudoers
```

### Python Version Issues

If you have multiple Python versions:

```bash
# Use specific Python version
python3.10 -m pip install -r requirements.txt
python3.10 -m src.cli.cli --help
```

### Missing Dependencies

If specific modules are missing:

```bash
# Reinstall all dependencies
pip install --upgrade --force-reinstall -r requirements.txt

# Or install specific modules
pip install fastapi uvicorn paramiko psutil
```

### Nmap Not Found

Some scanners require nmap:

```bash
# Ubuntu/Debian
sudo apt install nmap

# CentOS/RHEL
sudo yum install nmap

# Alpine
apk add nmap
```

## Post-Installation

### 1. Create Log Directory

```bash
sudo mkdir -p /var/log/clay-sec-audit
sudo chown -R $(whoami) /var/log/clay-sec-audit
```

### 2. Create Backup Directory

```bash
sudo mkdir -p /var/lib/clay-sec-audit/backups
sudo mkdir -p /var/lib/clay-sec-audit/reports
sudo mkdir -p /var/lib/clay-sec-audit/transactions
sudo chown -R root /var/lib/clay-sec-audit
```

### 3. Set File Permissions

```bash
# Make config files readable only by owner
chmod 600 ~/.clay-sec-audit/*

# Make reports directory accessible
sudo chmod 755 /var/lib/clay-sec-audit/reports
```

### 4. Configure Logging

```bash
# Create logging configuration
cat > ~/.clay-sec-audit/logging.json << 'EOF'
{
  "version": 1,
  "disable_existing_loggers": false,
  "formatters": {
    "standard": {
      "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    }
  },
  "handlers": {
    "default": {
      "level": "INFO",
      "class": "logging.StreamHandler",
      "formatter": "standard",
      "stream": "ext://sys.stdout"
    },
    "file": {
      "level": "DEBUG",
      "class": "logging.FileHandler",
      "formatter": "standard",
      "filename": "/var/log/clay-sec-audit/audit.log"
    }
  },
  "loggers": {
    "": {
      "handlers": ["default", "file"],
      "level": "INFO",
      "propagate": false
    }
  }
}
EOF
```

## Uninstallation

```bash
# Remove package
pip uninstall clay-sec-audit

# Remove configuration and data
rm -rf ~/.clay-sec-audit
sudo rm -rf /var/lib/clay-sec-audit
sudo rm -rf /var/log/clay-sec-audit
```

## Getting Started

After installation, try:

```bash
# Run initial scan
sudo claysecaudit scan --save-report

# View security score
claysecaudit score

# Generate reports
claysecaudit report --format both

# Start web dashboard
python -m uvicorn src.dashboard.api:app --host 0.0.0.0 --port 8000
```

See [usage.md](usage.md) for detailed usage instructions.
