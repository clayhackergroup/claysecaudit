"""Port scanner using nmap"""
import logging
import re
from typing import Dict, List, Optional
from .utils import ScannerBase, Finding

logger = logging.getLogger(__name__)


class PortScanner(ScannerBase):
    """Scan for open ports and risky services"""

    RISKY_SERVICES = {
        6379: {"service": "Redis", "severity": "critical", "reason": "Database exposed without auth"},
        27017: {"service": "MongoDB", "severity": "critical", "reason": "NoSQL database exposed"},
        27018: {"service": "MongoDB", "severity": "critical", "reason": "NoSQL database exposed"},
        3306: {"service": "MySQL", "severity": "high", "reason": "Database exposed to network"},
        5432: {"service": "PostgreSQL", "severity": "high", "reason": "Database exposed to network"},
        5984: {"service": "CouchDB", "severity": "critical", "reason": "NoSQL database exposed"},
        9200: {"service": "Elasticsearch", "severity": "critical", "reason": "Search engine exposed"},
        9300: {"service": "Elasticsearch", "severity": "critical", "reason": "Elasticsearch cluster port"},
        21: {"service": "FTP", "severity": "high", "reason": "Unencrypted file transfer"},
        23: {"service": "Telnet", "severity": "critical", "reason": "Unencrypted remote access"},
        25: {"service": "SMTP", "severity": "medium", "reason": "Exposed SMTP relay"},
        135: {"service": "RPC", "severity": "high", "reason": "Windows RPC exposed"},
        445: {"service": "SMB", "severity": "high", "reason": "File sharing exposed"},
        3389: {"service": "RDP", "severity": "high", "reason": "Remote desktop exposed"},
        8080: {"service": "HTTP-Alt", "severity": "medium", "reason": "Alternate web port"},
    }

    def __init__(self, hostname: str = "localhost"):
        super().__init__(hostname)
        self.open_ports: Dict[int, str] = {}

    def scan(self) -> Dict[str, any]:
        """Scan for open ports using netstat/ss"""
        logger.info(f"Starting port scan on {self.hostname}")

        # Use ss command for local scanning (more reliable than nmap without root)
        stdout, stderr, returncode = self.execute_local_command("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")

        if returncode != 0:
            logger.warning("Failed to scan ports with ss/netstat")
            return {"open_ports": {}, "risky_services": []}

        self._parse_port_output(stdout)
        self._check_risky_services()

        risky = [f.to_dict() for f in self.findings]

        return {
            "open_ports": self.open_ports,
            "risky_services": risky,
            "total_findings": len(self.findings),
            "severity_score": self.calculate_severity_score()
        }

    def _parse_port_output(self, output: str):
        """Parse ss/netstat output"""
        lines = output.split('\n')
        for line in lines:
            if 'LISTEN' not in line:
                continue

            # Parse lines like: tcp  0 0 127.0.0.1:3306
            match = re.search(r'(\d+\.\d+\.\d+\.\d+|::?):(\d+)\s+.*LISTEN', line)
            if match:
                port = int(match.group(2))
                self.open_ports[port] = self._get_service_name(port)

    def _get_service_name(self, port: int) -> str:
        """Get service name for port"""
        common_services = {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
        }
        return common_services.get(port, f"Unknown-{port}")

    def _check_risky_services(self):
        """Check for risky service exposure"""
        for port, service_name in self.open_ports.items():
            if port in self.RISKY_SERVICES:
                risk = self.RISKY_SERVICES[port]
                finding = Finding(
                    id=f"port_{port}",
                    category="Port Security",
                    severity=risk["severity"],
                    title=f"Risky Service Exposed: {risk['service']}",
                    description=f"Port {port} ({risk['service']}) is open and listening. {risk['reason']}",
                    affected_resource=f"0.0.0.0:{port}",
                    remediation=f"Restrict access to port {port} using firewall rules or bind to localhost only",
                )
                self.add_finding(finding)
