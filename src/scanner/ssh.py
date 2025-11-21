"""SSH configuration auditor"""
import logging
import re
from typing import Dict, List
from .utils import ScannerBase, Finding

logger = logging.getLogger(__name__)


class SSHAuditor(ScannerBase):
    """Audit SSH configuration for security issues"""

    WEAK_CIPHERS = [
        "3des-cbc", "aes128-cbc", "aes256-cbc", "arcfour", "arcfour128", "arcfour256"
    ]

    WEAK_KEY_EXCHANGE = [
        "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1"
    ]

    def __init__(self, hostname: str = "localhost"):
        super().__init__(hostname)
        self.ssh_config_path = "/etc/ssh/sshd_config"
        self.config_content = ""

    def scan(self) -> Dict[str, any]:
        """Scan SSH configuration"""
        logger.info(f"Starting SSH audit on {self.hostname}")

        if not self.file_exists(self.ssh_config_path):
            logger.error(f"SSH config not found at {self.ssh_config_path}")
            return {"findings": [], "ssh_enabled": False}

        self.config_content = self.read_file(self.ssh_config_path) or ""

        self._check_root_login()
        self._check_password_auth()
        self._check_weak_ciphers()
        self._check_weak_key_exchange()
        self._check_fail2ban()
        self._check_key_based_auth()
        self._check_permit_empty_passwords()
        self._check_x11_forwarding()
        self._check_port_number()

        findings = [f.to_dict() for f in self.findings]

        return {
            "findings": findings,
            "ssh_enabled": True,
            "total_findings": len(self.findings),
            "severity_score": self.calculate_severity_score()
        }

    def _get_config_value(self, key: str) -> str:
        """Extract SSH config value"""
        pattern = rf"^\s*{key}\s+(.+?)(?:\s*#.*)?$"
        match = re.search(pattern, self.config_content, re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else ""

    def _check_root_login(self):
        """Check if root login is allowed"""
        permit_root = self._get_config_value("PermitRootLogin")
        if permit_root.lower() in ["yes", ""]:
            finding = Finding(
                id="ssh_root_login",
                category="SSH Security",
                severity="critical",
                title="Root Login Allowed",
                description="SSH permits direct root login. Attackers can target the root account directly.",
                affected_resource=self.ssh_config_path,
                remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart SSH",
            )
            self.add_finding(finding)

    def _check_password_auth(self):
        """Check if password authentication is enabled"""
        pass_auth = self._get_config_value("PasswordAuthentication")
        if pass_auth.lower() in ["yes", ""]:
            finding = Finding(
                id="ssh_password_auth",
                category="SSH Security",
                severity="high",
                title="Password Authentication Enabled",
                description="SSH allows password-based authentication, vulnerable to brute-force attacks.",
                affected_resource=self.ssh_config_path,
                remediation="Set 'PasswordAuthentication no' and use key-based auth instead",
            )
            self.add_finding(finding)

    def _check_weak_ciphers(self):
        """Check for weak ciphers"""
        ciphers = self._get_config_value("Ciphers")
        if ciphers:
            for weak in self.WEAK_CIPHERS:
                if weak in ciphers.lower():
                    finding = Finding(
                        id="ssh_weak_ciphers",
                        category="SSH Security",
                        severity="high",
                        title="Weak SSH Ciphers",
                        description=f"Weak cipher '{weak}' is enabled in SSH config",
                        affected_resource=self.ssh_config_path,
                        remediation="Remove weak ciphers and use only modern ones like aes256-ctr, chacha20-poly1305",
                    )
                    self.add_finding(finding)
                    break

    def _check_weak_key_exchange(self):
        """Check for weak key exchange algorithms"""
        kex = self._get_config_value("KexAlgorithms")
        if kex:
            for weak in self.WEAK_KEY_EXCHANGE:
                if weak in kex.lower():
                    finding = Finding(
                        id="ssh_weak_kex",
                        category="SSH Security",
                        severity="high",
                        title="Weak SSH Key Exchange",
                        description=f"Weak key exchange algorithm '{weak}' is enabled",
                        affected_resource=self.ssh_config_path,
                        remediation="Remove weak KEX algorithms and use curve25519-sha256, diffie-hellman-group16-sha512",
                    )
                    self.add_finding(finding)
                    break

    def _check_fail2ban(self):
        """Check if fail2ban is installed and running"""
        stdout, _, returncode = self.execute_local_command("systemctl is-active fail2ban 2>/dev/null")
        if returncode != 0:
            finding = Finding(
                id="ssh_no_fail2ban",
                category="SSH Security",
                severity="medium",
                title="fail2ban Not Active",
                description="fail2ban is not running. SSH brute-force attacks are not rate-limited.",
                affected_resource="fail2ban service",
                remediation="Install and enable fail2ban: sudo apt install fail2ban && sudo systemctl enable fail2ban",
            )
            self.add_finding(finding)

    def _check_key_based_auth(self):
        """Check if key-based authentication is configured"""
        pub_keys = self._get_config_value("AuthorizedKeysFile")
        if not pub_keys or pub_keys == "":
            finding = Finding(
                id="ssh_no_pubkey_auth",
                category="SSH Security",
                severity="medium",
                title="No Public Key Authentication",
                description="Public key authentication may not be configured",
                affected_resource=self.ssh_config_path,
                remediation="Configure 'AuthorizedKeysFile ~/.ssh/authorized_keys' and add SSH public keys",
            )
            self.add_finding(finding)

    def _check_permit_empty_passwords(self):
        """Check if empty passwords are permitted"""
        empty_pass = self._get_config_value("PermitEmptyPasswords")
        if empty_pass.lower() == "yes":
            finding = Finding(
                id="ssh_empty_passwords",
                category="SSH Security",
                severity="critical",
                title="Empty Passwords Permitted",
                description="SSH permits login with empty passwords",
                affected_resource=self.ssh_config_path,
                remediation="Set 'PermitEmptyPasswords no'",
            )
            self.add_finding(finding)

    def _check_x11_forwarding(self):
        """Check if X11 forwarding is disabled"""
        x11 = self._get_config_value("X11Forwarding")
        if x11.lower() in ["yes", ""]:
            finding = Finding(
                id="ssh_x11_forwarding",
                category="SSH Security",
                severity="medium",
                title="X11 Forwarding Enabled",
                description="X11 forwarding can be exploited for local privilege escalation",
                affected_resource=self.ssh_config_path,
                remediation="Set 'X11Forwarding no'",
            )
            self.add_finding(finding)

    def _check_port_number(self):
        """Check if SSH is running on non-standard port"""
        port = self._get_config_value("Port")
        if port == "" or port == "22":
            finding = Finding(
                id="ssh_standard_port",
                category="SSH Security",
                severity="low",
                title="SSH Running on Standard Port",
                description="SSH is on port 22 (default), making it an obvious attack target",
                affected_resource=self.ssh_config_path,
                remediation="Change SSH port to a non-standard number (e.g., 2222) using 'Port 2222'",
            )
            self.add_finding(finding)
