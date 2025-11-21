# Clay Sec Audit - API Documentation

## Overview

Clay Sec Audit provides a RESTful API via FastAPI for programmatic access to all security scanning, fixing, and reporting functionality.

**Base URL**: `http://localhost:8000`
**Swagger UI**: `http://localhost:8000/docs`
**ReDoc**: `http://localhost:8000/redoc`

## Authentication

Current version uses no authentication. In production, implement:

```python
from fastapi.security import HTTPBearer
security = HTTPBearer()

@app.post("/scan")
async def start_scan(request: ScanRequest, credentials: HTTPAuthCredentials = Depends(security)):
    # Validate token
    pass
```

## Endpoints

### Health Check

**GET** `/health`

Check if API is running and healthy.

```bash
curl http://localhost:8000/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00",
  "version": "1.0.0"
}
```

---

### Start Scan

**POST** `/scan`

Begin a security scan on the target system.

**Request Body**:
```json
{
  "hostname": "localhost",
  "scanners": ["ssh", "ports", "nginx"]
}
```

**Parameters**:
- `hostname` (string, required): Target hostname or IP address
- `scanners` (array, optional): List of scanners to run. Omit to run all.
  - Valid values: `ssh`, `ports`, `nginx`, `apache`, `filesystem`, `database`, `api`

**Response** (200 OK):
```json
{
  "audit_id": "abc123def456",
  "status": "started",
  "message": "Scan started with audit ID: abc123def456"
}
```

**Example**:
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "192.168.1.100",
    "scanners": ["ssh", "ports"]
  }'
```

---

### Get Scan Status

**GET** `/scan/{audit_id}`

Retrieve the status and results of a scan.

**Path Parameters**:
- `audit_id` (string): The unique audit ID returned from scan start

**Response** (200 OK):
```json
{
  "audit_id": "abc123def456",
  "status": "completed",
  "started_at": "2024-01-15T10:30:00",
  "completed_at": "2024-01-15T10:31:30",
  "progress": 100,
  "overall_score": 72.5,
  "findings_summary": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2
  },
  "results": {
    "ssh_auditor": {
      "findings": [...],
      "total_findings": 2,
      "severity_score": {"critical": 0, "high": 2, "medium": 0, "low": 0}
    },
    "port_scanner": {
      "findings": [...],
      "total_findings": 1
    }
  }
}
```

**Status Values**:
- `running`: Scan in progress
- `completed`: Scan finished successfully
- `failed`: Scan encountered an error

**Example**:
```bash
curl http://localhost:8000/scan/abc123def456
```

---

### Apply Fix

**POST** `/fix/{finding_id}`

Apply a security fix for a specific finding.

**Path Parameters**:
- `finding_id` (string): The ID of the finding to fix

**Request Body**:
```json
{
  "dry_run": false,
  "rollback_on_failure": true
}
```

**Parameters**:
- `dry_run` (boolean, default: true): Preview changes without applying
- `rollback_on_failure` (boolean, default: true): Auto-rollback if fix fails

**Response** (200 OK):
```json
{
  "status": "success",
  "message": "SSH root login disabled",
  "finding_id": "ssh_root_login",
  "fixed": true,
  "changes": [
    {
      "file": "/etc/ssh/sshd_config",
      "action": "modified",
      "backup": "/var/lib/clay-sec-audit/backups/sshd_config.20240115_103000.bak"
    }
  ]
}
```

**Example - Dry Run**:
```bash
curl -X POST http://localhost:8000/fix/ssh_root_login \
  -H "Content-Type: application/json" \
  -d '{"dry_run": true}'
```

**Example - Apply Fix**:
```bash
curl -X POST http://localhost:8000/fix/ssh_root_login \
  -H "Content-Type: application/json" \
  -d '{"dry_run": false}'
```

---

### Generate Report

**GET** `/report/{audit_id}`

Generate a report from scan results.

**Path Parameters**:
- `audit_id` (string): The audit ID to generate report for

**Query Parameters**:
- `format` (string, default: json): Report format
  - `json`: JSON report
  - `pdf`: PDF report

**Response - JSON** (200 OK):
```json
{
  "audit_id": "abc123def456",
  "timestamp": "2024-01-15T10:31:30",
  "system_info": {
    "hostname": "myserver",
    "platform": "linux",
    "kernel": "5.10.0-8-generic"
  },
  "security_score": 72.5,
  "summary": {
    "total_findings": 11,
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2
  },
  "scanners": {
    "ssh_auditor": {
      "findings": [...],
      "total_findings": 2
    }
  }
}
```

**Response - PDF** (200 OK):
Binary PDF file with `Content-Type: application/pdf`

**Example - JSON Report**:
```bash
curl http://localhost:8000/report/abc123def456?format=json
```

**Example - PDF Report**:
```bash
curl http://localhost:8000/report/abc123def456?format=pdf > report.pdf
```

---

### Get Scan Logs

**GET** `/logs/{audit_id}`

Retrieve logs from a scan execution.

**Path Parameters**:
- `audit_id` (string): The audit ID

**Response** (200 OK):
```json
{
  "audit_id": "abc123def456",
  "logs": [
    {
      "timestamp": "2024-01-15T10:30:00",
      "message": "Starting port scan..."
    },
    {
      "timestamp": "2024-01-15T10:30:05",
      "message": "Found 8 open ports"
    }
  ]
}
```

**Example**:
```bash
curl http://localhost:8000/logs/abc123def456
```

---

### WebSocket - Real-time Logs

**WS** `/ws/scan/{audit_id}`

Connect via WebSocket for real-time scan logs.

**Path Parameters**:
- `audit_id` (string): The audit ID

**Message Format**:
```json
{
  "audit_id": "abc123def456",
  "status": "running",
  "logs": [
    {
      "timestamp": "2024-01-15T10:30:00",
      "message": "Running SSH Auditor..."
    }
  ]
}
```

**Example - wscat**:
```bash
wscat -c ws://localhost:8000/ws/scan/abc123def456
```

**Example - Python**:
```python
import asyncio
import websockets
import json

async def listen_logs():
    uri = "ws://localhost:8000/ws/scan/abc123def456"
    async with websockets.connect(uri) as websocket:
        while True:
            data = await websocket.recv()
            logs = json.loads(data)
            for log in logs["logs"]:
                print(f"{log['timestamp']}: {log['message']}")

asyncio.run(listen_logs())
```

---

## Data Models

### ScanRequest
```python
{
  "hostname": str,           # Target hostname or IP
  "scanners": List[str]      # Optional: specific scanners to run
}
```

### FixRequest
```python
{
  "dry_run": bool = True,    # Preview without applying
  "rollback_on_failure": bool = True
}
```

### Finding
```python
{
  "id": str,                 # Unique finding ID
  "category": str,           # Security category
  "severity": str,           # critical, high, medium, low
  "title": str,              # Finding title
  "description": str,        # Detailed description
  "affected_resource": str,  # File, service, or resource
  "remediation": str,        # How to fix
  "cve": str | None,         # CVE ID if applicable
  "evidence": str | None     # Evidence/proof
}
```

### ScanResponse
```python
{
  "audit_id": str,
  "status": str,             # running, completed, failed
  "started_at": str,         # ISO timestamp
  "completed_at": str | None,
  "progress": int,           # 0-100
  "overall_score": float,    # 0-100
  "findings_summary": {
    "critical": int,
    "high": int,
    "medium": int,
    "low": int
  },
  "results": dict            # Scanner results
}
```

---

## Error Responses

### 404 Not Found
```json
{
  "error": "Audit not found",
  "audit_id": "invalid_id"
}
```

### 400 Bad Request
```json
{
  "error": "Invalid scanner name",
  "message": "Valid scanners are: ssh, ports, nginx, apache, filesystem, database, api"
}
```

### 500 Internal Server Error
```json
{
  "error": "Internal server error",
  "message": "Failed to start scan",
  "details": "Permission denied"
}
```

---

## Rate Limiting

Not implemented in v1.0. Consider adding for production:

```python
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.util import get_remote_address

@app.post("/scan")
@limiter.limit("10/minute")
async def start_scan(request: ScanRequest, request: Request):
    pass
```

---

## CORS Headers

All endpoints allow CORS requests:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type
```

---

## Usage Examples

### Python Client

```python
import requests
import time

BASE_URL = "http://localhost:8000"

# Start scan
response = requests.post(f"{BASE_URL}/scan", json={
    "hostname": "myserver.com",
    "scanners": ["ssh", "ports"]
})
audit_id = response.json()["audit_id"]
print(f"Started scan: {audit_id}")

# Poll for completion
while True:
    status = requests.get(f"{BASE_URL}/scan/{audit_id}").json()
    print(f"Progress: {status['progress']}%")
    
    if status["status"] == "completed":
        print(f"Security Score: {status['overall_score']}/100")
        print(f"Findings: {status['findings_summary']}")
        break
    
    time.sleep(2)

# Get report
report = requests.get(f"{BASE_URL}/report/{audit_id}?format=json").json()
print(f"Report ID: {report['audit_id']}")

# Get logs
logs = requests.get(f"{BASE_URL}/logs/{audit_id}").json()
for log in logs["logs"]:
    print(f"{log['timestamp']}: {log['message']}")
```

### JavaScript/Node.js Client

```javascript
const BASE_URL = "http://localhost:8000";

// Start scan
const scanRes = await fetch(`${BASE_URL}/scan`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    hostname: "myserver.com",
    scanners: ["ssh", "ports"]
  })
});

const { audit_id } = await scanRes.json();

// WebSocket for real-time logs
const ws = new WebSocket(`ws://localhost:8000/ws/scan/${audit_id}`);
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(`Status: ${data.status}`);
  data.logs.forEach(log => {
    console.log(`${log.timestamp}: ${log.message}`);
  });
};
```

### cURL Examples

```bash
# Start scan
AUDIT_ID=$(curl -s -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"hostname":"localhost"}' | jq -r .audit_id)

# Poll status
curl http://localhost:8000/scan/$AUDIT_ID | jq .progress

# Download JSON report
curl http://localhost:8000/report/$AUDIT_ID?format=json > report.json

# Download PDF report  
curl http://localhost:8000/report/$AUDIT_ID?format=pdf > report.pdf
```

---

## WebSocket Connection Lifecycle

```
Client                          Server
  │                               │
  │────── WS CONNECT ────────────>│
  │                               │ Accepts connection
  │<────── WS ACCEPT ─────────────│
  │                               │
  │<────── LOG MESSAGE 1 ─────────│
  │<────── LOG MESSAGE 2 ─────────│
  │<────── LOG MESSAGE 3 ─────────│
  │                               │
  │ (polling messages until      │
  │  status changes to completed)│
  │                               │
  │────── WS CLOSE ───────────────>│
  │                               │
```

---

## Troubleshooting

### "Connection refused"
Ensure API server is running:
```bash
python -m uvicorn src.dashboard.api:app --host 0.0.0.0 --port 8000
```

### "Permission denied" errors
Ensure CLI tool is running with proper privileges:
```bash
sudo python -m uvicorn src.dashboard.api:app --host 0.0.0.0 --port 8000
```

### Slow scan response
- Use `scanners` parameter to run only needed scanners
- Check target system load
- Monitor API logs for errors

### WebSocket disconnections
- Ensure firewall allows WebSocket traffic
- Check for proxy/load balancer issues
- Implement client-side reconnection logic

---

## Changelog

### v1.0.0
- Initial release
- Core scan endpoints
- Fix application endpoint
- Report generation
- Real-time logs via WebSocket

---

For more information, see [usage.md](usage.md) and [architecture.md](architecture.md).
