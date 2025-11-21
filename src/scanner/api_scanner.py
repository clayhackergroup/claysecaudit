"""API security scanner"""
import logging
from typing import Dict
from .utils import ScannerBase, Finding

logger = logging.getLogger(__name__)


class APISecurityScanner(ScannerBase):
    """Scan for API security issues"""

    def __init__(self, hostname: str = "localhost"):
        super().__init__(hostname)

    def scan(self) -> Dict[str, any]:
        """Scan for API security issues"""
        logger.info(f"Starting API security scan on {self.hostname}")

        self._check_cors_misconfig()
        self._check_debug_endpoints()
        self._check_api_documentation()

        findings = [f.to_dict() for f in self.findings]

        return {
            "findings": findings,
            "total_findings": len(self.findings),
            "severity_score": self.calculate_severity_score()
        }

    def _check_cors_misconfig(self):
        """Check for CORS misconfigurations"""
        # Check common web server configs for CORS
        stdout, _, _ = self.execute_local_command(
            "grep -r 'Access-Control-Allow-Origin' /etc/nginx /etc/apache2 2>/dev/null | grep '\\*'"
        )

        if stdout.strip():
            finding = Finding(
                id="api_cors_wildcard",
                category="API Security",
                severity="high",
                title="CORS Wildcard Allowed",
                description="Access-Control-Allow-Origin is set to '*', allowing any origin",
                affected_resource="Web server config",
                remediation="Set specific allowed origins instead of '*'",
                evidence=stdout[:300]
            )
            self.add_finding(finding)

    def _check_debug_endpoints(self):
        """Check for debug endpoints"""
        # Check for common debug endpoints in web server configs
        debug_patterns = [
            "debug",
            "/admin",
            "/api/v1/debug",
            "/?debug=",
            "/swagger",
            "/docs"
        ]

        for pattern in debug_patterns:
            stdout, _, _ = self.execute_local_command(
                f"grep -ri '{pattern}' /etc/nginx /etc/apache2 /var/www 2>/dev/null | head -5"
            )

            if stdout.strip() and "swagger" in stdout.lower() and "debug" not in pattern:
                # Swagger is okay
                continue

            if stdout.strip() and "swagger" not in stdout.lower():
                finding = Finding(
                    id=f"api_debug_{pattern.replace('/', '_')}",
                    category="API Security",
                    severity="medium",
                    title="Potential Debug Endpoint",
                    description=f"Debug or admin endpoint '{pattern}' may be exposed",
                    affected_resource="Web application",
                    remediation=f"Disable or protect debug endpoint '{pattern}'",
                    evidence=stdout[:300]
                )
                self.add_finding(finding)
                break

    def _check_api_documentation(self):
        """Check for exposed API documentation"""
        doc_paths = [
            "/swagger-ui.html",
            "/api/docs",
            "/api/v1/docs",
            "/docs",
            "/graphql",
            "/api"
        ]

        exposed = []
        for path in doc_paths:
            stdout, _, _ = self.execute_local_command(f"curl -s -I http://localhost{path} 2>/dev/null | head -1")
            if stdout.strip() and "200" in stdout or "301" in stdout or "302" in stdout:
                exposed.append(path)

        if exposed:
            finding = Finding(
                id="api_docs_exposed",
                category="API Security",
                severity="medium",
                title="API Documentation Exposed",
                description=f"API documentation is publicly accessible: {', '.join(exposed)}",
                affected_resource="localhost",
                remediation="Restrict access to API documentation using authentication or firewall rules"
            )
            self.add_finding(finding)
