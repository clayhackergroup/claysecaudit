"""Scanner utility functions"""
import os
import subprocess
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a security finding"""
    id: str
    category: str
    severity: str  # critical, high, medium, low
    title: str
    description: str
    affected_resource: str
    remediation: str
    cve: Optional[str] = None
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ScannerBase:
    """Base class for all scanners"""

    def __init__(self, hostname: str = "localhost", port: int = 22, username: str = "root", password: Optional[str] = None):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.findings: List[Finding] = []
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    def execute_local_command(self, command: str) -> Tuple[str, str, int]:
        """Execute command locally"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timeout", 1
        except Exception as e:
            return "", str(e), 1

    def file_exists(self, path: str) -> bool:
        """Check if file exists locally"""
        return os.path.exists(path)

    def read_file(self, path: str) -> Optional[str]:
        """Read file content"""
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    return f.read()
        except Exception as e:
            logger.error(f"Failed to read {path}: {e}")
        return None

    def add_finding(self, finding: Finding):
        """Add a finding to the scan results"""
        self.findings.append(finding)

    def calculate_severity_score(self) -> Dict[str, int]:
        """Calculate severity distribution"""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        for finding in self.findings:
            if finding.severity in severity_counts:
                severity_counts[finding.severity] += 1
        return severity_counts

    def get_overall_score(self) -> float:
        """Calculate overall security score (0-100)"""
        if not self.findings:
            return 100.0

        severity_weights = {"critical": 40, "high": 25, "medium": 10, "low": 5}
        total_score = 0

        for finding in self.findings:
            weight = severity_weights.get(finding.severity, 5)
            total_score += weight

        # Cap at 100, decrease from 100
        return max(0, 100 - min(100, total_score))

    def get_findings_by_severity(self) -> Dict[str, List[Finding]]:
        """Group findings by severity"""
        result = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        for finding in self.findings:
            if finding.severity in result:
                result[finding.severity].append(finding)
        return result
