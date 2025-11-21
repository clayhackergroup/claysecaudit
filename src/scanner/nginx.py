"""Nginx configuration auditor"""
import logging
import os
import re
from typing import Dict
from .utils import ScannerBase, Finding

logger = logging.getLogger(__name__)


class NginxAuditor(ScannerBase):
    """Audit Nginx configuration for security issues"""

    def __init__(self, hostname: str = "localhost"):
        super().__init__(hostname)
        self.nginx_config_paths = [
            "/etc/nginx/nginx.conf",
            "/etc/nginx/conf.d/",
            "/etc/nginx/sites-enabled/"
        ]

    def scan(self) -> Dict[str, any]:
        """Scan Nginx configuration"""
        logger.info(f"Starting Nginx audit on {self.hostname}")

        # Check if nginx is installed
        stdout, _, returncode = self.execute_local_command("which nginx 2>/dev/null")
        if returncode != 0:
            logger.info("Nginx not installed")
            return {"findings": [], "nginx_enabled": False}

        # Check if nginx is running
        stdout, _, returncode = self.execute_local_command("systemctl is-active nginx 2>/dev/null")
        is_running = returncode == 0

        self._scan_nginx_config()
        self._check_ssl_tls()
        self._check_security_headers()
        self._check_directory_listing()
        self._check_server_tokens()
        self._check_http_methods()

        findings = [f.to_dict() for f in self.findings]

        return {
            "findings": findings,
            "nginx_enabled": True,
            "nginx_running": is_running,
            "total_findings": len(self.findings),
            "severity_score": self.calculate_severity_score()
        }

    def _scan_nginx_config(self):
        """Scan all nginx config files"""
        for path in self.nginx_config_paths:
            if os.path.isfile(path):
                content = self.read_file(path)
                if content:
                    self._analyze_config(content, path)
            elif os.path.isdir(path):
                for filename in os.listdir(path):
                    filepath = os.path.join(path, filename)
                    if os.path.isfile(filepath) and filename.endswith(".conf"):
                        content = self.read_file(filepath)
                        if content:
                            self._analyze_config(content, filepath)

    def _analyze_config(self, content: str, filepath: str):
        """Analyze single config file"""
        if "server_tokens on" in content:
            finding = Finding(
                id="nginx_server_tokens",
                category="Web Server Security",
                severity="medium",
                title="Server Version Exposed",
                description="Nginx server tokens are enabled, exposing version information",
                affected_resource=filepath,
                remediation="Add 'server_tokens off;' to nginx.conf",
            )
            self.add_finding(finding)

        if re.search(r"autoindex\s+on", content):
            finding = Finding(
                id="nginx_directory_listing",
                category="Web Server Security",
                severity="high",
                title="Directory Listing Enabled",
                description="Directory listing is enabled, exposing server contents",
                affected_resource=filepath,
                remediation="Set 'autoindex off;' in location blocks",
            )
            self.add_finding(finding)

    def _check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        for path in self.nginx_config_paths:
            content = self._read_config_path(path)
            if not content:
                continue

            # Check for weak SSL protocols
            if re.search(r"ssl_protocols.*SSLv2|ssl_protocols.*SSLv3|ssl_protocols.*TLSv1[^.]", content):
                finding = Finding(
                    id="nginx_weak_ssl",
                    category="Web Server Security",
                    severity="high",
                    title="Weak SSL/TLS Versions",
                    description="Nginx supports weak SSL/TLS versions (SSLv2, SSLv3, TLSv1.0)",
                    affected_resource=path,
                    remediation="Set 'ssl_protocols TLSv1.2 TLSv1.3;'",
                )
                self.add_finding(finding)

            # Check for missing HSTS
            if "add_header Strict-Transport-Security" not in content:
                finding = Finding(
                    id="nginx_no_hsts",
                    category="Web Server Security",
                    severity="medium",
                    title="HSTS Header Missing",
                    description="Strict-Transport-Security header is not set",
                    affected_resource=path,
                    remediation="Add 'add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;'",
                )
                self.add_finding(finding)

    def _check_security_headers(self):
        """Check for missing security headers"""
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY or SAMEORIGIN",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        }

        for path in self.nginx_config_paths:
            content = self._read_config_path(path)
            if not content:
                continue

            for header, value in headers.items():
                if f"add_header {header}" not in content:
                    finding = Finding(
                        id=f"nginx_missing_{header.replace('-', '_').lower()}",
                        category="Web Server Security",
                        severity="medium",
                        title=f"Missing {header} Header",
                        description=f"Security header '{header}' is not set",
                        affected_resource=path,
                        remediation=f"Add 'add_header {header} \"{value}\" always;'",
                    )
                    self.add_finding(finding)

    def _check_directory_listing(self):
        """Check for directory listing issues"""
        for path in self.nginx_config_paths:
            content = self._read_config_path(path)
            if not content:
                continue

            if re.search(r"autoindex\s+on", content):
                finding = Finding(
                    id="nginx_autoindex",
                    category="Web Server Security",
                    severity="high",
                    title="Directory Listing Enabled",
                    description="Directory listing (autoindex) is enabled",
                    affected_resource=path,
                    remediation="Set 'autoindex off;' in all location blocks",
                )
                self.add_finding(finding)
                break

    def _check_server_tokens(self):
        """Check server token exposure"""
        for path in self.nginx_config_paths:
            content = self._read_config_path(path)
            if not content:
                continue

            if "server_tokens on" in content or "server_tokens" not in content:
                finding = Finding(
                    id="nginx_tokens",
                    category="Web Server Security",
                    severity="low",
                    title="Server Version Exposed",
                    description="Nginx reveals server version and OS",
                    affected_resource=path,
                    remediation="Set 'server_tokens off;'",
                )
                self.add_finding(finding)
                break

    def _check_http_methods(self):
        """Check if unnecessary HTTP methods are allowed"""
        for path in self.nginx_config_paths:
            content = self._read_config_path(path)
            if not content:
                continue

            # If there's no explicit method restriction, it's potentially risky
            if "limit_except GET HEAD POST" not in content:
                # This is more of a recommendation
                pass

    def _read_config_path(self, path: str) -> str:
        """Safely read config path"""
        content = ""
        if os.path.isfile(path):
            content = self.read_file(path) or ""
        elif os.path.isdir(path):
            for filename in os.listdir(path):
                if filename.endswith(".conf"):
                    file_content = self.read_file(os.path.join(path, filename)) or ""
                    content += file_content + "\n"
        return content
