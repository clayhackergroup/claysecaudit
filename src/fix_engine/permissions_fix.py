"""File permissions fixes"""
import logging
import os
import stat
import subprocess
from typing import Tuple
from .backup import BackupManager
from .rollback import Transaction

logger = logging.getLogger(__name__)


class PermissionsFixer:
    """Fix file permission issues"""

    def __init__(self):
        self.backup_manager = BackupManager()

    def fix_world_writable(self, filepath: str, transaction: Transaction) -> Tuple[bool, str]:
        """Remove world-writable permissions"""
        if not os.path.exists(filepath):
            return False, f"File not found: {filepath}"

        try:
            # Get current permissions
            current_stat = os.stat(filepath)
            current_mode = current_stat.st_mode

            # Remove others write permission
            new_mode = current_mode & ~stat.S_IWOTH

            # Backup before change
            backup_path = self.backup_manager.backup_file(filepath)
            if backup_path:
                transaction.add_operation("file_modify", filepath, backup_path)

            # Apply new permissions
            os.chmod(filepath, new_mode)

            logger.info(f"Fixed world-writable permissions for {filepath}")
            return True, f"Removed world-writable permission (mode: {oct(current_mode)} -> {oct(new_mode)})"

        except Exception as e:
            logger.error(f"Failed to fix {filepath}: {e}")
            return False, str(e)

    def fix_private_key_permissions(self, filepath: str, transaction: Transaction) -> Tuple[bool, str]:
        """Fix private key permissions to 600"""
        if not os.path.exists(filepath):
            return False, f"File not found: {filepath}"

        try:
            backup_path = self.backup_manager.backup_file(filepath)
            if backup_path:
                transaction.add_operation("file_modify", filepath, backup_path)

            os.chmod(filepath, 0o600)
            logger.info(f"Fixed private key permissions: {filepath}")
            return True, "Private key permissions set to 600"

        except Exception as e:
            logger.error(f"Failed to fix private key {filepath}: {e}")
            return False, str(e)

    def fix_shadow_permissions(self, transaction: Transaction) -> Tuple[bool, str]:
        """Fix /etc/shadow permissions to 640"""
        shadow_file = "/etc/shadow"
        if not os.path.exists(shadow_file):
            return False, "File not found: /etc/shadow"

        try:
            backup_path = self.backup_manager.backup_file(shadow_file)
            if backup_path:
                transaction.add_operation("file_modify", shadow_file, backup_path)

            os.chmod(shadow_file, 0o640)
            logger.info(f"Fixed /etc/shadow permissions")
            return True, "/etc/shadow permissions set to 640"

        except Exception as e:
            logger.error(f"Failed to fix /etc/shadow: {e}")
            return False, str(e)

    def fix_passwd_permissions(self, transaction: Transaction) -> Tuple[bool, str]:
        """Fix /etc/passwd permissions to 644"""
        passwd_file = "/etc/passwd"
        if not os.path.exists(passwd_file):
            return False, "File not found: /etc/passwd"

        try:
            backup_path = self.backup_manager.backup_file(passwd_file)
            if backup_path:
                transaction.add_operation("file_modify", passwd_file, backup_path)

            os.chmod(passwd_file, 0o644)
            logger.info(f"Fixed /etc/passwd permissions")
            return True, "/etc/passwd permissions set to 644"

        except Exception as e:
            logger.error(f"Failed to fix /etc/passwd: {e}")
            return False, str(e)

    def fix_sudoers_permissions(self, transaction: Transaction) -> Tuple[bool, str]:
        """Fix /etc/sudoers permissions to 440"""
        sudoers_file = "/etc/sudoers"
        if not os.path.exists(sudoers_file):
            return False, "File not found: /etc/sudoers"

        try:
            backup_path = self.backup_manager.backup_file(sudoers_file)
            if backup_path:
                transaction.add_operation("file_modify", sudoers_file, backup_path)

            os.chmod(sudoers_file, 0o440)
            logger.info(f"Fixed /etc/sudoers permissions")
            return True, "/etc/sudoers permissions set to 440"

        except Exception as e:
            logger.error(f"Failed to fix /etc/sudoers: {e}")
            return False, str(e)

    def fix_tmp_permissions(self, transaction: Transaction) -> Tuple[bool, str]:
        """Fix /tmp sticky bit and permissions"""
        tmp_dir = "/tmp"
        if not os.path.exists(tmp_dir):
            return False, "Directory not found: /tmp"

        try:
            backup_path = self.backup_manager.backup_file(tmp_dir)
            if backup_path:
                transaction.add_operation("file_modify", tmp_dir, backup_path)

            # Set mode 1777 (sticky bit + rwx for all)
            os.chmod(tmp_dir, 0o1777)
            logger.info(f"Fixed /tmp permissions")
            return True, "/tmp permissions set to 1777 (sticky bit enabled)"

        except Exception as e:
            logger.error(f"Failed to fix /tmp: {e}")
            return False, str(e)

    def fix_batch_permissions(self, filepaths: list, target_mode: int, transaction: Transaction) -> Tuple[bool, str]:
        """Fix permissions for multiple files"""
        failed = []
        fixed = []

        for filepath in filepaths:
            try:
                if os.path.exists(filepath):
                    backup_path = self.backup_manager.backup_file(filepath)
                    if backup_path:
                        transaction.add_operation("file_modify", filepath, backup_path)

                    os.chmod(filepath, target_mode)
                    fixed.append(filepath)
            except Exception as e:
                failed.append((filepath, str(e)))

        if failed:
            msg = f"Fixed {len(fixed)} files, failed {len(failed)}: {', '.join([f[0] for f in failed])}"
            return False, msg

        return True, f"Fixed permissions for {len(fixed)} files to {oct(target_mode)}"
