"""SSH hardening fixes"""
import logging
import subprocess
import os
from typing import Tuple
from .backup import BackupManager
from .rollback import RollbackManager, Transaction

logger = logging.getLogger(__name__)


class SSHFixer:
    """Fix SSH security issues"""

    def __init__(self):
        self.backup_manager = BackupManager()
        self.rollback_manager = RollbackManager(self.backup_manager)
        self.ssh_config_path = "/etc/ssh/sshd_config"

    def fix_root_login(self, transaction: Transaction) -> Tuple[bool, str]:
        """Fix root login permission"""
        if not os.path.exists(self.ssh_config_path):
            return False, "SSH config not found"

        # Backup before modification
        backup_path = self.backup_manager.backup_file(self.ssh_config_path)
        if not backup_path:
            return False, "Failed to backup SSH config"

        transaction.add_operation("file_modify", self.ssh_config_path, backup_path)

        try:
            with open(self.ssh_config_path, 'r') as f:
                content = f.read()

            # Replace or add PermitRootLogin no
            if "PermitRootLogin" in content:
                import re
                content = re.sub(r"^#?\s*PermitRootLogin\s+.*$", "PermitRootLogin no", content, flags=re.MULTILINE)
            else:
                content += "\nPermitRootLogin no\n"

            with open(self.ssh_config_path, 'w') as f:
                f.write(content)

            # Test SSH config
            result = subprocess.run(["sshd", "-t"], capture_output=True)
            if result.returncode != 0:
                logger.error(f"SSH config test failed: {result.stderr.decode()}")
                self.backup_manager.restore_file(backup_path, self.ssh_config_path)
                return False, "SSH config validation failed"

            # Restart SSH
            subprocess.run(["systemctl", "restart", "ssh"], capture_output=True)

            logger.info("Successfully fixed root login permission")
            return True, "PermitRootLogin set to no"

        except Exception as e:
            logger.error(f"Failed to fix root login: {e}")
            self.backup_manager.restore_file(backup_path, self.ssh_config_path)
            return False, str(e)

    def fix_password_auth(self, transaction: Transaction) -> Tuple[bool, str]:
        """Disable password authentication"""
        if not os.path.exists(self.ssh_config_path):
            return False, "SSH config not found"

        backup_path = self.backup_manager.backup_file(self.ssh_config_path)
        if not backup_path:
            return False, "Failed to backup SSH config"

        transaction.add_operation("file_modify", self.ssh_config_path, backup_path)

        try:
            with open(self.ssh_config_path, 'r') as f:
                content = f.read()

            import re
            if "PasswordAuthentication" in content:
                content = re.sub(r"^#?\s*PasswordAuthentication\s+.*$", "PasswordAuthentication no", 
                               content, flags=re.MULTILINE)
            else:
                content += "\nPasswordAuthentication no\n"

            with open(self.ssh_config_path, 'w') as f:
                f.write(content)

            # Test and restart
            result = subprocess.run(["sshd", "-t"], capture_output=True)
            if result.returncode != 0:
                self.backup_manager.restore_file(backup_path, self.ssh_config_path)
                return False, "SSH config validation failed"

            subprocess.run(["systemctl", "restart", "ssh"], capture_output=True)

            logger.info("Successfully disabled password authentication")
            return True, "PasswordAuthentication disabled"

        except Exception as e:
            logger.error(f"Failed to fix password auth: {e}")
            self.backup_manager.restore_file(backup_path, self.ssh_config_path)
            return False, str(e)

    def fix_x11_forwarding(self, transaction: Transaction) -> Tuple[bool, str]:
        """Disable X11 forwarding"""
        if not os.path.exists(self.ssh_config_path):
            return False, "SSH config not found"

        backup_path = self.backup_manager.backup_file(self.ssh_config_path)
        if not backup_path:
            return False, "Failed to backup SSH config"

        transaction.add_operation("file_modify", self.ssh_config_path, backup_path)

        try:
            with open(self.ssh_config_path, 'r') as f:
                content = f.read()

            import re
            if "X11Forwarding" in content:
                content = re.sub(r"^#?\s*X11Forwarding\s+.*$", "X11Forwarding no", 
                               content, flags=re.MULTILINE)
            else:
                content += "\nX11Forwarding no\n"

            with open(self.ssh_config_path, 'w') as f:
                f.write(content)

            result = subprocess.run(["sshd", "-t"], capture_output=True)
            if result.returncode != 0:
                self.backup_manager.restore_file(backup_path, self.ssh_config_path)
                return False, "SSH config validation failed"

            subprocess.run(["systemctl", "restart", "ssh"], capture_output=True)

            logger.info("Successfully disabled X11 forwarding")
            return True, "X11Forwarding disabled"

        except Exception as e:
            logger.error(f"Failed to fix X11 forwarding: {e}")
            self.backup_manager.restore_file(backup_path, self.ssh_config_path)
            return False, str(e)

    def fix_empty_passwords(self, transaction: Transaction) -> Tuple[bool, str]:
        """Disable empty password authentication"""
        if not os.path.exists(self.ssh_config_path):
            return False, "SSH config not found"

        backup_path = self.backup_manager.backup_file(self.ssh_config_path)
        if not backup_path:
            return False, "Failed to backup SSH config"

        transaction.add_operation("file_modify", self.ssh_config_path, backup_path)

        try:
            with open(self.ssh_config_path, 'r') as f:
                content = f.read()

            import re
            if "PermitEmptyPasswords" in content:
                content = re.sub(r"^#?\s*PermitEmptyPasswords\s+.*$", "PermitEmptyPasswords no", 
                               content, flags=re.MULTILINE)
            else:
                content += "\nPermitEmptyPasswords no\n"

            with open(self.ssh_config_path, 'w') as f:
                f.write(content)

            result = subprocess.run(["sshd", "-t"], capture_output=True)
            if result.returncode != 0:
                self.backup_manager.restore_file(backup_path, self.ssh_config_path)
                return False, "SSH config validation failed"

            subprocess.run(["systemctl", "restart", "ssh"], capture_output=True)

            logger.info("Successfully disabled empty passwords")
            return True, "PermitEmptyPasswords disabled"

        except Exception as e:
            logger.error(f"Failed to disable empty passwords: {e}")
            self.backup_manager.restore_file(backup_path, self.ssh_config_path)
            return False, str(e)
