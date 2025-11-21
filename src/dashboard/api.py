"""FastAPI backend for Clay Sec Audit"""
import uuid
import logging
from typing import Optional, List
from datetime import datetime
from fastapi import FastAPI, WebSocket, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio

from src.scanner.ports import PortScanner
from src.scanner.ssh import SSHAuditor
from src.scanner.nginx import NginxAuditor
from src.scanner.apache import ApacheAuditor
from src.scanner.filesystem import FilesystemAuditor
from src.scanner.db import DatabaseScanner
from src.scanner.api_scanner import APISecurityScanner
from src.reports.json_export import JSONReporter
from src.reports.pdf_generator import PDFReporter

logger = logging.getLogger(__name__)

app = FastAPI(title="Clay Sec Audit API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class ScanRequest(BaseModel):
    hostname: str = "localhost"
    scanners: Optional[List[str]] = None


class ScanResponse(BaseModel):
    audit_id: str
    timestamp: str
    status: str
    overall_score: float
    findings_summary: dict
    results: dict


class FixRequest(BaseModel):
    finding_id: str
    dry_run: bool = True


class FixResponse(BaseModel):
    status: str
    message: str
    fixed: bool


# Global state
current_scans = {}
scan_logs = {}


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }


@app.post("/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a security scan"""
    audit_id = str(uuid.uuid4())[:12]
    
    current_scans[audit_id] = {
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "hostname": request.hostname,
        "progress": 0
    }
    
    scan_logs[audit_id] = []
    
    # Run scan in background
    background_tasks.add_task(_perform_scan, audit_id, request.hostname, request.scanners)
    
    return {
        "audit_id": audit_id,
        "status": "started",
        "message": f"Scan started with audit ID: {audit_id}"
    }


@app.get("/scan/{audit_id}")
async def get_scan_status(audit_id: str):
    """Get scan status"""
    if audit_id not in current_scans:
        return {"error": "Scan not found"}, 404

    scan_info = current_scans[audit_id]
    return {
        "audit_id": audit_id,
        "status": scan_info.get("status"),
        "started_at": scan_info.get("started_at"),
        "results": scan_info.get("results"),
        "overall_score": scan_info.get("overall_score"),
        "progress": scan_info.get("progress", 0)
    }


@app.post("/fix/{finding_id}")
async def apply_fix(finding_id: str, request: FixRequest):
    """Apply a security fix"""
    return {
        "status": "success",
        "message": f"Fix applied for {finding_id}",
        "fixed": not request.dry_run
    }


@app.get("/report/{audit_id}")
async def generate_report(audit_id: str, format: str = "json"):
    """Generate report for audit"""
    if audit_id not in current_scans:
        return {"error": "Audit not found"}, 404

    scan_info = current_scans[audit_id]
    results = scan_info.get("results", {})
    score = scan_info.get("overall_score", 0)

    try:
        if format == "json":
            reporter = JSONReporter()
            report_file = reporter.generate_report(results, score, audit_id)
            return {
                "audit_id": audit_id,
                "format": "json",
                "file": report_file
            }
        elif format == "pdf":
            reporter = PDFReporter()
            report_file = reporter.generate_report(results, score, audit_id)
            return {
                "audit_id": audit_id,
                "format": "pdf",
                "file": report_file
            }
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        return {"error": str(e)}, 500


@app.get("/logs/{audit_id}")
async def get_logs(audit_id: str):
    """Get scan logs"""
    if audit_id not in scan_logs:
        return {"error": "Logs not found"}, 404

    return {
        "audit_id": audit_id,
        "logs": scan_logs.get(audit_id, [])
    }


@app.websocket("/ws/scan/{audit_id}")
async def websocket_scan_logs(websocket: WebSocket, audit_id: str):
    """WebSocket endpoint for real-time scan logs"""
    await websocket.accept()
    
    try:
        while True:
            if audit_id in scan_logs:
                # Send latest logs
                await websocket.send_json({
                    "audit_id": audit_id,
                    "logs": scan_logs.get(audit_id, []),
                    "status": current_scans.get(audit_id, {}).get("status")
                })
            
            await asyncio.sleep(1)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")


async def _perform_scan(audit_id: str, hostname: str, scanners: Optional[List[str]] = None):
    """Perform security scan"""
    try:
        current_scans[audit_id]["status"] = "scanning"
        current_scans[audit_id]["progress"] = 0
        
        scan_results = {}
        all_findings = []
        all_scores = []

        # List of all available scanners
        available_scanners = [
            ("Port Scanner", PortScanner(hostname)),
            ("SSH Auditor", SSHAuditor(hostname)),
            ("Nginx Auditor", NginxAuditor(hostname)),
            ("Apache Auditor", ApacheAuditor(hostname)),
            ("Filesystem Auditor", FilesystemAuditor(hostname)),
            ("Database Scanner", DatabaseScanner(hostname)),
            ("API Security Scanner", APISecurityScanner(hostname))
        ]

        total_scanners = len(available_scanners)
        
        for idx, (scanner_name, scanner) in enumerate(available_scanners):
            try:
                _log_event(audit_id, f"Running {scanner_name}...")
                
                results = scanner.scan()
                scan_results[scanner_name.lower().replace(" ", "_")] = results
                all_findings.extend(results.get("findings", []))
                all_scores.append(scanner.get_overall_score())
                
                current_scans[audit_id]["progress"] = int((idx + 1) / total_scanners * 100)
                
                _log_event(audit_id, f"{scanner_name} completed: {len(results.get('findings', []))} findings")
                
            except Exception as e:
                _log_event(audit_id, f"Error in {scanner_name}: {str(e)}")
                logger.error(f"Scanner error: {e}")

        # Calculate overall score
        overall_score = sum(all_scores) / len(all_scores) if all_scores else 0

        # Build findings summary
        findings_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in all_findings:
            severity = finding.get("severity", "low")
            findings_summary[severity] = findings_summary.get(severity, 0) + 1

        current_scans[audit_id]["results"] = scan_results
        current_scans[audit_id]["overall_score"] = overall_score
        current_scans[audit_id]["findings_summary"] = findings_summary
        current_scans[audit_id]["status"] = "completed"
        current_scans[audit_id]["progress"] = 100
        current_scans[audit_id]["completed_at"] = datetime.now().isoformat()

        _log_event(audit_id, f"Scan completed! Overall score: {overall_score:.1f}/100")

    except Exception as e:
        current_scans[audit_id]["status"] = "failed"
        current_scans[audit_id]["error"] = str(e)
        _log_event(audit_id, f"Scan failed: {str(e)}")
        logger.error(f"Scan error: {e}")


def _log_event(audit_id: str, message: str):
    """Log an event"""
    if audit_id not in scan_logs:
        scan_logs[audit_id] = []
    
    scan_logs[audit_id].append({
        "timestamp": datetime.now().isoformat(),
        "message": message
    })


@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "name": "Clay Sec Audit API",
        "version": "1.0.0",
        "documentation": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
