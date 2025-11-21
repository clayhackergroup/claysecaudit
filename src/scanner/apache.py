"""Apache configuration auditor"""
import logging
import os
import re
from typing import Dict
from .utils import ScannerBase, Finding

logger = logging.getLogger(__name__)


class ApacheAuditor(ScannerBase):
    """Audit Apache configuration for security issues"""

    def __init__(self, hostname: str = "localhost"):
        super().__init__(hostname)
        self.apache_config_paths = [
            "/etc/apache2/apache2.conf",
            "/etc/apache2/conf-enabled/",
            "/etc/apache2/sites-enabled/",
            "/etc/httpd/conf/httpd.conf",
            "/etc/httpd/conf.d/"
        ]

    def scan(self) -> Dict[str, any]:
        """Scan Apache configuration"""
        logger.info(f"Starting Apache audit on {self.hostname}")

        # Check if Apache is installed
        stdout, _, returncode = self.execute_local_command("which apache2 apache2ctl httpd apachectl 2>/dev/null | head -1")
        if returncode != 0:
            logger.info("Apache not installed")
            return {"findings": [], "apache_enabled": False}

        # Check if Apache is running
        stdout, _, returncode = self.execute_local_command(
            "systemctl is-active apache2 2>/dev/null || systemctl is-active httpd 2>/dev/null"
        )
        is_running = returncode == 0

        self._scan_apache_config()
        self._check_ssl_tls()
        self._check_security_headers()
        self._check_directory_listing()
        self._check_server_tokens()

        findings = [f.to_dict() for f in self.findings]

        return {
            "findings": findings,
            "apache_enabled": True,
            "apache_running": is_running,
            "total_findings": len(self.findings),
            "severity_score": self.calculate_severity_score()
        }

    def _scan_apache_config(self):
        """Scan all Apache config files"""
        for path in self.apache_config_paths:
            if os.path.isfile(path):
                content = self.read_file(path)
                if content:
                    self._analyze_config(content, path)
            elif os.path.isdir(path):
                try:
                    for filename in os.listdir(path):
                        if filename.endswith(".conf"):
                            filepath = os.path.join(path, filename)
                            if os.path.isfile(filepath):
                                content = self.read_file(filepath)
                                if content:
                                    self._analyze_config(content, filepath)
                except PermissionError:
                    logger.warning(f"Permission denied reading {path}")

    def _analyze_config(self, content: str, filepath: str):
        """Analyze single config file"""
        # Check ServerTokens
        if re.search(r"ServerTokens\s+Full|ServerTokens\s+OS", content, re.IGNORECASE):
            finding = Finding(
                id="apache_server_tokens",
                category="Web Server Security",
                severity="medium",
                title="Server Version Exposed",
                description="ServerTokens is set to Full or OS, exposing Apache version",
                affected_resource=filepath,
                remediation="Set 'ServerTokens Prod' to hide version information",
            )
            self.add_finding(finding)

        # Check ServerSignature
        if re.search(r"ServerSignature\s+On", content, re.IGNORECASE):
            finding = Finding(
                id="apache_server_signature",
                category="Web Server Security",
                severity="low",
                title="Server Signature Enabled",
                description="ServerSignature includes version info in error pages",
                affected_resource=filepath,
                remediation="Set 'ServerSignature Off'",
            )
            self.add_finding(finding)

        # Check for Options Indexes
        if re.search(r"Options\s+.*Indexes", content, re.IGNORECASE):
            finding = Finding(
                id="apache_directory_listing",
                category="Web Server Security",
                severity="high",
                title="Directory Listing Enabled",
                description="Options Indexes is enabled, allowing directory browsing",
                affected_resource=filepath,
                remediation="Remove 'Indexes' from Options directive or add 'Options -Indexes'",
            )
            self.add_finding(finding)

    def _check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        for path in self.apache_config_paths:
            content = self._read_config_path(path)
            if not content:
                continue

            # Check for weak SSL protocols
            if re.search(r"SSLProtocol.*SSLv2|SSLProtocol.*SSLv3|SSLProtocol.*TLSv1\s", content, re.IGNORECASE):
                finding = Finding(
                    id="apache_weak_ssl",
                    category="Web Server Security",
                    severity="high",
                    title="Weak SSL/TLS Versions",
                    description="Apache supports weak SSL/TLS versions",
                    affected_resource=path,
                    remediation="Set 'SSLProtocol TLSv1.2 TLSv1.3'",
                )
                self.add_finding(finding)

            # Check for weak ciphers
            if re.search(r"SSLCipherSuite.*DES|SSLCipherSuite.*RC4|SSLCipherSuite.*MD5", content, re.IGNORECASE):
                finding = Finding(
                    id="apache_weak_ciphers",
                    category="Web Server Security",
                    severity="high",
                    title="Weak SSL Ciphers",
                    description="Weak cipher suites are enabled",
                    affected_resource=path,
                    remediation="Use modern cipher suite: SSLCipherSuite 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'",
                )
                self.add_finding(finding)

    def _check_security_headers(self):
        """Check for missing security headers"""
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000"
        }

        for path in self.apache_config_paths:
            content = self._read_config_path(path)
            if not content:
                continue

            for header in headers.keys():
                if f"Header set {header}" not in content and f"Header always set {header}" not in content:
                    finding = Finding(
                        id=f"apache_missing_{header.replace('-', '_').lower()}",
                        category="Web Server Security",
                        severity="medium",
                        title=f"Missing {header} Header",
                        description=f"Security header '{header}' is not configured",
                        affected_resource=path,
                        remediation=f"Add 'Header always set {header} value' in Apache config",
                    )
                    self.add_finding(finding)

    def _check_directory_listing(self):
        """Check for directory listing"""
        for path in self.apache_config_paths:
            content = self._read_config_path(path)
            if not content:
                continue

            if re.search(r"Options\s+.*Indexes", content, re.IGNORECASE):
                finding = Finding(
                    id="apache_indexes",
                    category="Web Server Security",
                    severity="high",
                    title="Directory Listing Enabled",
                    description="Directory indexing is enabled",
                    affected_resource=path,
                    remediation="Add 'Options -Indexes' to disable directory listing",
                )
                self.add_finding(finding)
                break

    def _check_server_tokens(self):
        """Check server token exposure"""
        for path in self.apache_config_paths:
            content = self._read_config_path(path)
            if not content:
                continue

            if "ServerTokens Prod" not in content:
                finding = Finding(
                    id="apache_tokens",
                    category="Web Server Security",
                    severity="low",
                    title="Excessive Server Information",
                    description="Apache exposes too much version information",
                    affected_resource=path,
                    remediation="Set 'ServerTokens Prod' and 'ServerSignature Off'",
                )
                self.add_finding(finding)
                break

    def _read_config_path(self, path: str) -> str:
        """Safely read config path"""
        content = ""
        if os.path.isfile(path):
            content = self.read_file(path) or ""
        elif os.path.isdir(path):
            try:
                for filename in os.listdir(path):
                    if filename.endswith(".conf"):
                        file_content = self.read_file(os.path.join(path, filename)) or ""
                        content += file_content + "\n"
            except PermissionError:
                logger.warning(f"Permission denied reading {path}")
        return content
