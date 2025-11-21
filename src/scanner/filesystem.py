"""File system security auditor"""
import logging
import os
import stat
from typing import Dict, List
from .utils import ScannerBase, Finding

logger = logging.getLogger(__name__)


class FilesystemAuditor(ScannerBase):
    """Audit filesystem permissions for security issues"""

    SENSITIVE_PATHS = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh",
        "/home",
        "/var/www",
        "/srv",
    ]

    SENSITIVE_FILES = [
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
        "/home/*/.ssh/id_rsa",
        "/home/*/.ssh/id_ed25519",
        "/etc/ssl/private/",
    ]

    def __init__(self, hostname: str = "localhost"):
        super().__init__(hostname)

    def scan(self) -> Dict[str, any]:
        """Scan filesystem for security issues"""
        logger.info(f"Starting filesystem audit on {self.hostname}")

        self._check_world_writable()
        self._check_private_keys()
        self._check_sensitive_files()
        self._check_suid_binaries()
        self._check_temp_permissions()

        findings = [f.to_dict() for f in self.findings]

        return {
            "findings": findings,
            "total_findings": len(self.findings),
            "severity_score": self.calculate_severity_score()
        }

    def _check_world_writable(self):
        """Check for world-writable files and directories"""
        stdout, _, _ = self.execute_local_command("find / -type f -perm -002 2>/dev/null | head -20")

        if stdout.strip():
            finding = Finding(
                id="fs_world_writable",
                category="File Permissions",
                severity="high",
                title="World-Writable Files Found",
                description="Files/directories with world-writable permissions (o+w) detected",
                affected_resource="/various",
                remediation="Remove write permission for others: chmod o-w <file>",
                evidence=stdout[:500]
            )
            self.add_finding(finding)

    def _check_private_keys(self):
        """Check for exposed private keys"""
        # Check common private key locations
        private_key_patterns = [
            "/root/.ssh/id_rsa",
            "/root/.ssh/id_ed25519",
            "/home/*/.ssh/id_rsa",
            "/home/*/.ssh/id_ed25519",
        ]

        stdout, _, _ = self.execute_local_command(
            "find /root /home -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null | head -20"
        )

        if stdout.strip():
            # Check permissions
            for key_file in stdout.strip().split('\n'):
                if key_file:
                    stdout, _, _ = self.execute_local_command(f"stat -c '%a' '{key_file}' 2>/dev/null")
                    perms = stdout.strip()
                    if perms and perms != "600" and perms != "400":
                        finding = Finding(
                            id="fs_weak_key_perms",
                            category="File Permissions",
                            severity="critical",
                            title="Private Key with Weak Permissions",
                            description=f"Private key {key_file} has permissions {perms} (should be 600)",
                            affected_resource=key_file,
                            remediation=f"chmod 600 {key_file}"
                        )
                        self.add_finding(finding)

    def _check_sensitive_files(self):
        """Check permissions on sensitive files"""
        # /etc/shadow should be 600
        if os.path.exists("/etc/shadow"):
            stdout, _, _ = self.execute_local_command("stat -c '%a' /etc/shadow 2>/dev/null")
            perms = stdout.strip()
            if perms and perms != "640" and perms != "000":
                if not perms.startswith("0"):
                    finding = Finding(
                        id="fs_shadow_perms",
                        category="File Permissions",
                        severity="high",
                        title="Weak /etc/shadow Permissions",
                        description=f"/etc/shadow has permissions {perms}, should be 640 or 000",
                        affected_resource="/etc/shadow",
                        remediation="chmod 640 /etc/shadow"
                    )
                    self.add_finding(finding)

        # /etc/passwd should be readable but not writable by others
        if os.path.exists("/etc/passwd"):
            stdout, _, _ = self.execute_local_command("stat -c '%a' /etc/passwd 2>/dev/null")
            perms = stdout.strip()
            if perms and perms.endswith("2"):  # world-writable
                finding = Finding(
                    id="fs_passwd_writable",
                    category="File Permissions",
                    severity="critical",
                    title="/etc/passwd is World-Writable",
                    description="/etc/passwd has world-writable permissions",
                    affected_resource="/etc/passwd",
                    remediation="chmod 644 /etc/passwd"
                )
                self.add_finding(finding)

        # /etc/sudoers should be 440
        if os.path.exists("/etc/sudoers"):
            stdout, _, _ = self.execute_local_command("stat -c '%a' /etc/sudoers 2>/dev/null")
            perms = stdout.strip()
            if perms and perms != "440":
                finding = Finding(
                    id="fs_sudoers_perms",
                    category="File Permissions",
                    severity="high",
                    title="Weak /etc/sudoers Permissions",
                    description=f"/etc/sudoers has permissions {perms}, should be 440",
                    affected_resource="/etc/sudoers",
                    remediation="chmod 440 /etc/sudoers"
                )
                self.add_finding(finding)

    def _check_suid_binaries(self):
        """Check for SUID binaries (informational)"""
        stdout, _, _ = self.execute_local_command("find / -perm -4000 2>/dev/null | wc -l")
        count = stdout.strip()
        if count and int(count) > 50:
            finding = Finding(
                id="fs_many_suid",
                category="File Permissions",
                severity="low",
                title="Many SUID Binaries",
                description=f"Found {count} SUID binaries on system. Review if all are necessary.",
                affected_resource="/",
                remediation="Audit SUID binaries and disable unnecessary ones: chmod u-s <binary>"
            )
            self.add_finding(finding)

    def _check_temp_permissions(self):
        """Check /tmp and /var/tmp permissions"""
        temp_dirs = ["/tmp", "/var/tmp"]
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                stdout, _, _ = self.execute_local_command(f"stat -c '%a' {temp_dir} 2>/dev/null")
                perms = stdout.strip()
                if perms:
                    # /tmp should be 1777 (sticky bit + rwx for all)
                    if temp_dir == "/tmp" and perms != "1777":
                        finding = Finding(
                            id=f"fs_{temp_dir.replace('/', '')}_perms",
                            category="File Permissions",
                            severity="medium",
                            title=f"Weak {temp_dir} Permissions",
                            description=f"{temp_dir} has permissions {perms}, should be 1777",
                            affected_resource=temp_dir,
                            remediation=f"chmod 1777 {temp_dir}"
                        )
                        self.add_finding(finding)
